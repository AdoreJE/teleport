// Teleport
// Copyright (C) 2026 Gravitational, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tracessh "github.com/gravitational/teleport/api/observability/tracing/ssh"
	"github.com/gravitational/teleport/lib/uds"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// fluxTestOptions는 t의 임시 0700 디렉터리에 겹치지 않는 브리지 경로를 반환한다.
func fluxTestOptions(t *testing.T) SSHOptions {
	t.Helper()
	// macOS Unix 소켓 경로 길이 제한을 피한다.
	dir, err := os.MkdirTemp("/tmp", "s2-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return SSHOptions{FluxSFTPSocket: filepath.Join(dir, "s"), FluxControlSocket: filepath.Join(dir, "c")}
}

// TestFluxSFTPValidation은 t로 옵션 미사용·경로·실행 모드 검증을 확인한다.
func TestFluxSFTPValidation(t *testing.T) {
	for _, command := range [][]string{nil, {"ls"}} {
		for _, noExec := range []bool{false, true} {
			require.NoError(t, validateFluxSFTPOptions(SSHOptions{}, command, noExec))
		}
	}
	o := fluxTestOptions(t)
	require.NoError(t, validateFluxSFTPOptions(o, nil, false))
	require.Error(t, validateFluxSFTPOptions(o, []string{"ls"}, false))
	require.Error(t, validateFluxSFTPOptions(o, nil, true))
	dir := filepath.Dir(o.FluxSFTPSocket)
	require.NoError(t, os.Chmod(dir, 0755))
	require.Error(t, validateFluxSFTPOptions(o, nil, false))
	require.NoError(t, os.Chmod(dir, 0700))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(dir, link))
	linked := o
	linked.FluxSFTPSocket = filepath.Join(link, "s")
	require.Error(t, validateFluxSFTPOptions(linked, nil, false))
	if os.Geteuid() == 0 {
		require.NoError(t, os.Chown(dir, 1, -1))
		require.Error(t, validateFluxSFTPOptions(o, nil, false))
		require.NoError(t, os.Chown(dir, 0, -1))
	}
	o.FluxControlSocket = ""
	require.Error(t, validateFluxSFTPOptions(o, nil, false))
}

// TestFluxSFTPStderr는 t로 stderr 상한·계속 소비·제어문자 이스케이프를 확인한다.
func TestFluxSFTPStderr(t *testing.T) {
	s := &fluxStderr{}
	data := bytes.Repeat([]byte{27}, 128*1024)
	n, err := s.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Len(t, s.data, 64*1024)
	require.True(t, s.truncated)
	require.NotContains(t, s.detail(), "\x1b")
	require.Contains(t, s.detail(), "truncated")
}

// fluxTestSSH는 t, reject로 SFTP echo 또는 subsystem 거부 SSH 서버와 연결한 클라이언트를 반환한다.
func fluxTestSSH(t *testing.T, reject bool) *tracessh.Client {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		sc, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			conn.Close()
			return
		}
		defer sc.Close()
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			c, requests, err := ch.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for req := range requests {
					if req.Type != "subsystem" {
						req.Reply(false, nil)
						continue
					}
					req.Reply(!reject, nil)
					if reject {
						return
					}
					// 64 KiB를 넘는 stderr도 중계 데이터 흐름을 막으면 안 된다.
					c.Stderr().Write(bytes.Repeat([]byte("e"), 128*1024))
					io.Copy(c, c)
					return
				}
			}()
		}
	}()
	raw, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	cc, chans, reqs, err := ssh.NewClientConn(raw, l.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	require.NoError(t, err)
	c := tracessh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { c.Close() })
	return c
}

// TestFluxSFTPBridge는 제어 종료·0600·동일 연결 다중 채널·거부 알림을 확인한다.
// t는 테스트 실행 상태이며 반환값은 없다.
func TestFluxSFTPBridge(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "relay", true: "reject"}[reject], func(t *testing.T) {
			o := fluxTestOptions(t)
			c := fluxTestSSH(t, reject)
			b, err := startFluxSFTPBridge(context.Background(), c, o)
			require.NoError(t, err)
			defer b.close()
			control, err := net.Dial("unix", o.FluxControlSocket)
			require.NoError(t, err)
			defer control.Close()
			require.NoError(t, control.SetDeadline(time.Now().Add(10*time.Second)))
			decoder := json.NewDecoder(control)
			var event fluxBridgeEvent
			require.NoError(t, decoder.Decode(&event))
			require.Equal(t, "bridgeReady", event.Type)
			for _, p := range []string{o.FluxSFTPSocket, o.FluxControlSocket} {
				st, err := os.Stat(p)
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0600), st.Mode().Perm())
			}
			for i := 0; i < 2; i++ {
				data, err := net.Dial("unix", o.FluxSFTPSocket)
				require.NoError(t, err)
				require.NoError(t, data.SetDeadline(time.Now().Add(10*time.Second)))
				if reject {
					require.NoError(t, decoder.Decode(&event))
					require.Equal(t, "channelFailed", event.Type)
					require.Equal(t, "unknown", event.Reason)
					require.Equal(t, strconv.Itoa(i+1), event.ID)
				} else {
					_, err = io.WriteString(data, "sftp bytes")
					require.NoError(t, err)
					got := make([]byte, len("sftp bytes"))
					_, err = io.ReadFull(data, got)
					require.NoError(t, err)
					require.Equal(t, "sftp bytes", string(got))
				}
				data.Close()
			}
			status := 7
			b.emit(fluxBridgeEvent{Type: "shellExited", Status: &status})
			require.NoError(t, decoder.Decode(&event))
			require.Equal(t, "shellExited", event.Type)
			require.Equal(t, 7, *event.Status)
			require.NoError(t, json.NewEncoder(control).Encode(fluxBridgeEvent{Type: "finish"}))
			select {
			case <-b.ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("finish did not stop bridge")
			}
		})
	}
}

// TestFluxSFTPControlLoss는 t로 EOF·cancel·잘못된 제어 프레임의 즉시 종료를 확인한다.
func TestFluxSFTPControlLoss(t *testing.T) {
	for _, frame := range []string{"", `{"type":"cancel"}` + "\n", strings.Repeat(" ", 4096) + `{"type":"finish"}` + "\n", "{\n", `{"type":"other"}` + "\n"} {
		o := fluxTestOptions(t)
		b, err := startFluxSFTPBridge(context.Background(), nil, o)
		require.NoError(t, err)
		c, err := net.Dial("unix", o.FluxControlSocket)
		require.NoError(t, err)
		var ready fluxBridgeEvent
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, json.NewDecoder(c).Decode(&ready))
		if frame != "" {
			io.WriteString(c, frame)
		}
		if frame == "" {
			c.Close()
		}
		select {
		case <-b.ctx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("control loss did not stop bridge")
		}
		c.Close()
		b.close()
	}
}

// TestFluxSFTPBridgeFailed는 t로 SFTP 소켓 충돌 때 제어 소켓의 실패 통지를 확인한다.
func TestFluxSFTPBridgeFailed(t *testing.T) {
	o := fluxTestOptions(t)
	require.NoError(t, os.WriteFile(o.FluxSFTPSocket, []byte("keep"), 0600))
	b, err := startFluxSFTPBridge(context.Background(), nil, o)
	require.NoError(t, err)
	defer b.close()
	c, err := net.Dial("unix", o.FluxControlSocket)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	var event fluxBridgeEvent
	require.NoError(t, json.NewDecoder(c).Decode(&event))
	require.Equal(t, "bridgeFailed", event.Type)
	require.Equal(t, "unknown", event.Reason)
	data, err := os.ReadFile(o.FluxSFTPSocket)
	require.NoError(t, err)
	require.Equal(t, "keep", string(data))
}

// TestFluxSFTPPeerUID는 t로 다른 UID 연결을 닫은 뒤 다음 연결을 수락하는지 확인한다.
func TestFluxSFTPPeerUID(t *testing.T) {
	o := fluxTestOptions(t)
	l, err := fluxListen(o.FluxSFTPSocket)
	require.NoError(t, err)
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	result := make(chan error, 1)
	go func() {
		calls := 0
		c, err := fluxAccept(l, func(c net.Conn) (*uds.Creds, error) {
			calls++
			if calls == 1 {
				return &uds.Creds{UID: os.Geteuid() + 1}, nil
			}
			return uds.GetCreds(c)
		})
		if err == nil {
			accepted <- c
		}
		result <- err
	}()
	first, err := net.Dial("unix", o.FluxSFTPSocket)
	require.NoError(t, err)
	defer first.Close()
	require.NoError(t, first.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = first.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	second, err := net.Dial("unix", o.FluxSFTPSocket)
	require.NoError(t, err)
	defer second.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("next peer was not accepted")
	}
	require.NoError(t, <-result)
}

// TestFluxSFTPShellWait는 t로 셸 종료 후 유지·상태 보존·묵은 신호 무시와 종료 후 중단 요청·종료 경로를 확인한다.
func TestFluxSFTPShellWait(t *testing.T) {
	for _, end := range []string{"finish", "cancel", "controlLoss", "nodeLoss", "context", "exitError", "staleSignal"} {
		t.Run(end, func(t *testing.T) {
			o := fluxTestOptions(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b, err := startFluxSFTPBridge(ctx, nil, o)
			require.NoError(t, err)
			defer b.close()
			control, err := net.Dial("unix", o.FluxControlSocket)
			require.NoError(t, err)
			defer control.Close()
			require.NoError(t, control.SetDeadline(time.Now().Add(5*time.Second)))
			dec := json.NewDecoder(control)
			var event fluxBridgeEvent
			require.NoError(t, dec.Decode(&event))
			require.Equal(t, "bridgeReady", event.Type)
			tc := &TeleportClient{Config: Config{Stderr: io.Discard}}
			tc.SetExitStatus(7)
			shellDone, nodeDone := make(chan error, 1), make(chan error, 1)
			interrupts := make(chan os.Signal, 1)
			if end == "staleSignal" {
				interrupts <- os.Interrupt
			}
			done := make(chan error, 1)
			go func() { done <- tc.waitFluxSFTPShell(ctx, b, shellDone, nodeDone, interrupts) }()
			shellErr := errors.New("shell result")
			if end == "exitError" {
				shellDone <- &ssh.ExitError{}
			} else if end == "staleSignal" {
				shellDone <- nil
			} else {
				shellDone <- shellErr
			}
			require.NoError(t, dec.Decode(&event))
			require.Equal(t, "shellExited", event.Type)
			require.Equal(t, 7, *event.Status)
			select {
			case <-done:
				t.Fatal("shell exit returned before finish")
			case <-time.After(20 * time.Millisecond):
			}
			if end == "staleSignal" {
				require.NoError(t, control.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
				var timeout net.Error
				require.ErrorAs(t, dec.Decode(&event), &timeout)
				require.True(t, timeout.Timeout())
				require.NoError(t, control.SetReadDeadline(time.Time{}))
			} else {
				interrupts <- os.Interrupt
				require.NoError(t, dec.Decode(&event))
				require.Equal(t, "cancelRequested", event.Type)
			}
			switch end {
			case "controlLoss":
				control.Close()
			case "nodeLoss":
				nodeDone <- io.EOF
			case "context":
				cancel()
			default:
				frame := end
				if end == "exitError" || end == "staleSignal" {
					frame = "finish"
				}
				require.NoError(t, json.NewEncoder(control).Encode(fluxBridgeEvent{Type: frame}))
			}
			select {
			case err := <-done:
				switch end {
				case "exitError", "staleSignal":
					require.NoError(t, err)
				case "context":
					require.True(t, errors.Is(err, context.Canceled) || errors.Is(err, shellErr))
				default:
					require.ErrorIs(t, err, shellErr)
				}
				require.Equal(t, 7, tc.ExitStatus())
			case <-time.After(5 * time.Second):
				t.Fatal("shell wait did not stop")
			}
		})
	}
}

// TestFluxSFTPEventQueue는 t로 가득 찬 이벤트 큐의 송신자가 취소 시 풀리는지 확인한다.
func TestFluxSFTPEventQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &fluxSFTPBridge{ctx: ctx, events: make(chan fluxBridgeEvent, 32)}
	for i := 0; i < cap(b.events); i++ {
		b.emit(fluxBridgeEvent{})
	}
	done := make(chan struct{})
	go func() { b.emit(fluxBridgeEvent{}); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("full queue blocked cancellation")
	}
}

// TestFluxSFTPControlWriteFailure는 t로 제어 수신 정지 시 쓰기 만료가 가득 찬 큐까지 해제하는지 확인한다.
func TestFluxSFTPControlWriteFailure(t *testing.T) {
	o := fluxTestOptions(t)
	b, err := startFluxSFTPBridge(context.Background(), nil, o)
	require.NoError(t, err)
	defer b.close()
	c, err := net.Dial("unix", o.FluxControlSocket)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	var ready fluxBridgeEvent
	require.NoError(t, json.NewDecoder(c).Decode(&ready))
	done := make(chan struct{})
	go func() {
		// 소켓 버퍼보다 큰 이벤트로 쓰기를 막은 뒤 큐도 채운다.
		for i := 0; i < 64; i++ {
			b.emit(fluxBridgeEvent{Type: "channelFailed", Detail: strings.Repeat("x", 1024*1024)})
		}
		close(done)
	}()
	select {
	case <-b.ctx.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("control write deadline did not cancel bridge")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control write failure left queue blocked")
	}
}
