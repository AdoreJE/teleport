// Teleport
// Copyright (C) 2026 Gravitational, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	tracessh "github.com/gravitational/teleport/api/observability/tracing/ssh"
	"github.com/gravitational/teleport/lib/uds"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// WithFluxSFTPSockets는 sftpPath, controlPath를 SSH 옵션에 저장하는 콜백을 반환한다.
func WithFluxSFTPSockets(sftpPath, controlPath string) func(*SSHOptions) {
	return func(o *SSHOptions) { o.FluxSFTPSocket, o.FluxControlSocket = sftpPath, controlPath }
}

// validateFluxSFTPOptions는 o, command, noExec의 브리지 조합을 검사한다.
// 잘못된 경로·단독 플래그·비대화형 실행은 오류를 반환하며 미사용이면 nil을 반환한다.
func validateFluxSFTPOptions(o SSHOptions, command []string, noExec bool) error {
	if o.FluxSFTPSocket == "" && o.FluxControlSocket == "" {
		return nil
	}
	if !filepath.IsAbs(o.FluxSFTPSocket) || !filepath.IsAbs(o.FluxControlSocket) || filepath.Clean(o.FluxSFTPSocket) == filepath.Clean(o.FluxControlSocket) {
		return trace.BadParameter("flux bridge requires two distinct absolute socket paths")
	}
	if len(command) != 0 || noExec || o.LocalCommandExecutor != nil || o.forkAfterAuthentication() {
		return trace.BadParameter("flux bridge requires an interactive foreground shell")
	}
	for _, p := range []string{o.FluxSFTPSocket, o.FluxControlSocket} {
		st, err := os.Lstat(filepath.Dir(p))
		if err != nil {
			return trace.Wrap(err)
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !st.IsDir() || st.Mode().Perm() != 0700 || !ok || owner.Uid != uint32(os.Geteuid()) {
			return trace.BadParameter("flux socket directory must be owned by the current user, have mode 0700, and not be a symlink")
		}
	}
	return nil
}

type fluxBridgeEvent struct {
	Type   string `json:"type"`
	ID     string `json:"id,omitempty"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	Status *int   `json:"status,omitempty"`
}

type fluxSFTPBridge struct {
	ctx     context.Context
	cancel  context.CancelFunc
	events  chan fluxBridgeEvent
	control net.Listener
	sftp    net.Listener
	client  *tracessh.Client
}

// fluxListen는 path에 0600 Unix 소켓을 만들고 리스너를 반환한다.
// 기존 파일은 덮어쓰지 않으며 생성·권한 설정 오류를 반환한다.
func fluxListen(path string) (net.Listener, error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, trace.Wrap(err)
	}
	return l, nil
}

// fluxAccept는 l에서 현재 euid와 같은 peer만 받아 반환한다.
// getCreds로 UID를 조회하며 불일치·조회 실패 연결은 닫고 재시도한다. 리스너 종료 오류는 반환한다.
func fluxAccept(l net.Listener, getCreds func(net.Conn) (*uds.Creds, error)) (net.Conn, error) {
	for {
		c, err := l.Accept()
		if err != nil {
			return nil, err
		}
		creds, err := getCreds(c)
		if err == nil && creds.UID == os.Geteuid() {
			return c, nil
		}
		c.Close()
	}
}

// startFluxSFTPBridge는 ctx, client, o로 소켓을 열고 브리지를 반환한다.
// 제어 소켓 생성 실패는 오류로 반환하며 SFTP 소켓 실패는 bridgeFailed로 알린다.
func startFluxSFTPBridge(ctx context.Context, client *tracessh.Client, o SSHOptions) (*fluxSFTPBridge, error) {
	control, err := fluxListen(o.FluxControlSocket)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	b := &fluxSFTPBridge{ctx: ctx, cancel: cancel, events: make(chan fluxBridgeEvent, 32), control: control, client: client}
	b.sftp, err = fluxListen(o.FluxSFTPSocket)
	if err != nil {
		b.emit(fluxBridgeEvent{Type: "bridgeFailed", Reason: "unknown", Detail: fluxDetail(err.Error())})
	} else {
		b.emit(fluxBridgeEvent{Type: "bridgeReady"})
	}
	go b.serve()
	return b, nil
}

// emit는 e를 제어 채널에 넣고 종료 후에는 버린다. 반환값과 오류는 없다.
func (b *fluxSFTPBridge) emit(e fluxBridgeEvent) {
	select {
	case b.events <- e:
	case <-b.ctx.Done():
	}
}

// close는 브리지의 취소와 소켓 회수를 수행한다. 반환값과 오류는 없다.
func (b *fluxSFTPBridge) close() {
	b.cancel()
	b.control.Close()
	if b.sftp != nil {
		b.sftp.Close()
	}
}

// serve는 제어 연결에서 finish·cancel·EOF를 받으면 모든 중계를 중단한다.
// 송수신·프레임 오류도 브리지를 종료하며 오류를 외부로 반환하지 않는다.
func (b *fluxSFTPBridge) serve() {
	defer b.close()
	stop := context.AfterFunc(b.ctx, func() { b.control.Close() })
	defer stop()
	c, err := fluxAccept(b.control, uds.GetCreds)
	if err != nil {
		return
	}
	defer c.Close()
	stopConn := context.AfterFunc(b.ctx, func() { c.Close() })
	defer stopConn()
	go func() {
		enc := json.NewEncoder(c)
		for {
			select {
			case e := <-b.events:
				c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if enc.Encode(e) != nil {
					b.cancel()
					return
				}
			case <-b.ctx.Done():
				return
			}
		}
	}()
	if b.sftp != nil {
		go b.acceptSFTP()
	}
	scanner := bufio.NewScanner(c)
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		var e fluxBridgeEvent
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			return
		}
		switch e.Type {
		case "finish", "cancel":
			return
		default:
			return
		}
	}
}

// acceptSFTP는 연결마다 순차 ID를 배정하고 독립 SFTP 채널 중계를 시작한다.
// 리스너 오류 또는 브리지 취소 시 종료하며 오류를 반환하지 않는다.
func (b *fluxSFTPBridge) acceptSFTP() {
	for id := uint64(1); ; id++ {
		c, err := fluxAccept(b.sftp, uds.GetCreds)
		if err != nil {
			return
		}
		go b.relay(c, strconv.FormatUint(id, 10))
	}
}

// fluxDetail은 text의 제어문자를 이스케이프한 진단 문자열을 반환한다.
func fluxDetail(text string) string {
	quoted := strconv.QuoteToGraphic(text)
	return quoted[1 : len(quoted)-1]
}

type fluxStderr struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

// Write는 p 전체를 소비하되 처음 64 KiB만 저장한다. 소비 길이와 nil 오류를 반환한다.
func (s *fluxStderr) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(len(p), 64*1024-len(s.data))
	s.data = append(s.data, p[:n]...)
	s.truncated = s.truncated || n < len(p)
	return len(p), nil
}

// detail은 저장한 stderr의 안전한 스냅샷과 잘림 표시를 반환한다.
func (s *fluxStderr) detail() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	detail := fluxDetail(string(s.data))
	if s.truncated {
		detail += " [stderr truncated]"
	}
	return detail
}

// relay는 c, id를 같은 SSH 연결의 새 SFTP 세션으로 중계한다.
// 실패 시 channelFailed를 즉시 보내며 원인을 확인할 수 없으면 unknown을 사용한다.
func (b *fluxSFTPBridge) relay(c net.Conn, id string) {
	defer c.Close()
	stopConn := context.AfterFunc(b.ctx, func() { c.Close() })
	defer stopConn()
	s, err := b.client.NewSession(b.ctx)
	if err != nil {
		b.emit(fluxBridgeEvent{Type: "channelFailed", ID: id, Reason: "unknown", Detail: fluxDetail(err.Error())})
		return
	}
	defer s.Close()
	stopSession := context.AfterFunc(b.ctx, func() { s.Close() })
	defer stopSession()
	stderr := &fluxStderr{}
	// subsystem 요청 실패 때도 stderr가 SSH 창을 막지 않도록 즉시 배수한다.
	errOut, err := s.StderrPipe()
	if err != nil {
		b.emit(fluxBridgeEvent{Type: "channelFailed", ID: id, Reason: "unknown", Detail: fluxDetail(err.Error())})
		return
	}
	go io.Copy(stderr, errOut)
	in, err := s.StdinPipe()
	if err != nil {
		b.emit(fluxBridgeEvent{Type: "channelFailed", ID: id, Reason: "unknown", Detail: fluxDetail(err.Error())})
		return
	}
	out, err := s.StdoutPipe()
	if err != nil {
		b.emit(fluxBridgeEvent{Type: "channelFailed", ID: id, Reason: "unknown", Detail: fluxDetail(err.Error())})
		return
	}
	if err := s.RequestSubsystem(b.ctx, "sftp"); err != nil {
		b.emit(fluxBridgeEvent{Type: "channelFailed", ID: id, Reason: "unknown", Detail: fluxDetail(err.Error()) + " " + stderr.detail()})
		return
	}
	go func() { io.Copy(in, c); in.Close() }()
	_, copyErr := io.Copy(c, out)
	if copyErr != nil {
		b.emit(fluxBridgeEvent{Type: "channelFailed", ID: id, Reason: "unknown", Detail: fluxDetail(copyErr.Error()) + " " + stderr.detail()})
	}
}

// runFluxSFTPShell는 ctx, node, o로 셸과 브리지를 실행한다.
// 셸 종료 상태를 보존하며 finish·cancel·제어 단절·노드 단절까지 연결을 유지한다.
// 셸 생성·브리지 시작·컨텍스트 오류를 반환한다.
func (tc *TeleportClient) runFluxSFTPShell(ctx context.Context, node *NodeClient, o SSHOptions) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// 셸 종료 후 터미널 복원과 대기 루프 진입 사이에도 SIGINT를 소유한다.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	original := tc.OnShellCreated
	defer func() { tc.OnShellCreated = original }()
	started := make(chan *fluxSFTPBridge, 1)
	tc.OnShellCreated = func(s *tracessh.Session, c *tracessh.Client, terminal io.ReadWriteCloser) (bool, error) {
		if original != nil {
			exit, err := original(s, c, terminal)
			if exit || err != nil {
				return exit, err
			}
		}
		b, err := startFluxSFTPBridge(ctx, c, o)
		if err != nil {
			return true, err
		}
		started <- b
		return false, nil
	}
	shellDone := make(chan error, 1)
	go func() { shellDone <- node.RunInteractiveShell(ctx, "", "", nil) }()
	var b *fluxSFTPBridge
	select {
	case b = <-started:
	case err := <-shellDone:
		select {
		case b = <-started:
			shellDone <- err
		default:
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	defer b.close()
	nodeDone := make(chan error, 1)
	go func() { nodeDone <- node.Client.Wait() }()
	return tc.waitFluxSFTPShell(ctx, b, shellDone, nodeDone, interrupts)
}

// waitFluxSFTPShell은 ctx, b와 셸·노드 결과 및 신호 채널로 종료 후 대기를 수행한다.
// finish·cancel·제어 단절·노드 단절 때 셸 결과를 반환하고 ctx 취소는 컨텍스트 오류를 반환한다.
// 셸 실행 중 쌓인 신호를 버리고 SSH exit 오류는 저장된 종료 상태로 전달해 nil을 반환한다.
func (tc *TeleportClient) waitFluxSFTPShell(ctx context.Context, b *fluxSFTPBridge, shellDone, nodeDone <-chan error, interrupts <-chan os.Signal) error {
	var shellErr error
	select {
	case shellErr = <-shellDone:
	case <-b.ctx.Done():
		return nil
	case err := <-nodeDone:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
	// 셸 실행 중 원격으로 전달된 Ctrl-C는 종료 후 취소 요청으로 재사용하지 않는다.
drainInterrupts:
	for {
		select {
		case <-interrupts:
		default:
			break drainInterrupts
		}
	}
	var exitErr *ssh.ExitError
	if errors.As(trace.Unwrap(shellErr), &exitErr) {
		shellErr = nil
	}
	status := tc.ExitStatus()
	b.emit(fluxBridgeEvent{Type: "shellExited", Status: &status})
	for {
		select {
		case <-interrupts:
			b.emit(fluxBridgeEvent{Type: "cancelRequested"})
		case <-b.ctx.Done():
			return shellErr
		case <-nodeDone:
			return shellErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
