// Teleport
// Copyright (C) 2026 Gravitational, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"golang.org/x/sys/unix"

	"github.com/gravitational/teleport/api/client/proto"
	wancli "github.com/gravitational/teleport/lib/auth/webauthncli"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
)

const webauthnBridgeFrameLimit = 64 * 1024

// webauthnBridge는 연결과 읽기 버퍼를 유지해 후속 요청에서도 이전 응답을 검출한다.
type webauthnBridge struct {
	mu     sync.Mutex
	fd     string
	conn   net.Conn
	reader *bufio.Reader
	failed bool
}

// newWebauthnBridgeLogin은 fd 문자열을 보관한 로그인 콜백을 반환한다.
// 콜백은 FD, 프로토콜, 취소, 시간 제한 및 assertion 오류를 반환하며 다른 경로로 전환하지 않는다.
func newWebauthnBridgeLogin(fd string) WebauthnLoginFunc {
	return (&webauthnBridge{fd: fd}).login
}

// open은 b.fd의 소켓을 소유하고 CLOEXEC를 설정한다. 잘못된 FD나 소켓 변환 오류를 반환한다.
func (b *webauthnBridge) open() error {
	fd, err := strconv.Atoi(b.fd)
	if err != nil || fd < 3 {
		return trace.BadParameter("invalid WebAuthn bridge FD")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return trace.BadParameter("invalid WebAuthn bridge FD")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return trace.BadParameter("cannot secure WebAuthn bridge FD")
	}
	file := os.NewFile(uintptr(fd), "webauthn-bridge")
	defer file.Close()
	b.conn, err = net.FileConn(file)
	if err != nil {
		return trace.BadParameter("WebAuthn bridge FD must be a socket")
	}
	// 읽기 64KiB와 송신 64KiB로 보관하는 wire 버퍼 합계를 128KiB 이하로 제한한다.
	b.reader = bufio.NewReaderSize(b.conn, webauthnBridgeFrameLimit)
	return nil
}

// write는 value를 상한 내 NDJSON으로 보낸다. 크기 초과, JSON 변환 및 송신 오류는 내용을 제외하고 반환한다.
func (b *webauthnBridge) write(value any) error {
	frame, err := json.Marshal(value)
	if err != nil || len(frame)+1 > webauthnBridgeFrameLimit {
		return trace.BadParameter("invalid WebAuthn bridge outgoing frame")
	}
	frame = append(frame, '\n')
	for len(frame) > 0 {
		n, err := b.conn.Write(frame)
		if err != nil || n == 0 {
			return trace.ConnectionProblem(nil, "WebAuthn bridge write failed")
		}
		frame = frame[n:]
	}
	return nil
}

// login은 ctx와 assertion으로 FD 인증을 수행하고 MFA 응답과 빈 사용자명을 반환한다.
// origin, prompt, opts는 사용하지 않는다. FD, 검증, 취소, EOF, 프로토콜 및 시간 제한 오류를 반환한다.
func (b *webauthnBridge) login(ctx context.Context, _ string, assertion *wantypes.CredentialAssertion, _ wancli.LoginPrompt, _ *wancli.LoginOpts) (result *proto.MFAAuthenticateResponse, user string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed {
		return nil, "", trace.BadParameter("WebAuthn bridge already failed")
	}
	defer func() {
		if err != nil {
			b.failed = true
			if b.conn != nil {
				b.conn.Close()
			}
		}
	}()
	if err := assertion.Validate(); err != nil {
		return nil, "", trace.Wrap(err)
	}
	timeout := 120 * time.Second
	if ms := assertion.Response.Timeout; ms > 0 && ms < 120000 {
		timeout = time.Duration(ms) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, "", trace.Wrap(err)
	}
	first := b.conn == nil
	if first {
		if err := b.open(); err != nil {
			return nil, "", trace.Wrap(err)
		}
	}
	deadline, _ := ctx.Deadline()
	if err := b.conn.SetDeadline(deadline); err != nil {
		return nil, "", trace.ConnectionProblem(nil, "WebAuthn bridge deadline failed")
	}
	// 취소 콜백이 끝나기 전에 다음 요청의 deadline을 덮어쓰지 않도록 기다린다.
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { b.conn.SetDeadline(time.Now()); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	if first {
		if err := b.write(struct {
			V        int    `json:"v"`
			Type     string `json:"type"`
			Protocol string `json:"protocol"`
			Rev      int    `json:"rev"`
		}{1, "hello", "tsh-webauthn-bridge", 1}); err != nil {
			return nil, "", err
		}
	}
	id := uuid.NewString()
	if err := b.write(struct {
		V         int                                        `json:"v"`
		Type      string                                     `json:"type"`
		ID        string                                     `json:"id"`
		PublicKey wantypes.PublicKeyCredentialRequestOptions `json:"publicKey"`
	}{1, "assert", id, assertion.Response}); err != nil {
		return nil, "", err
	}
	frame, err := b.reader.ReadSlice('\n')
	if err != nil {
		return nil, "", trace.ConnectionProblem(nil, "WebAuthn bridge frame missing or oversized")
	}
	var response struct {
		V          int             `json:"v"`
		Type       string          `json:"type"`
		ID         string          `json:"id"`
		Credential json.RawMessage `json:"credential"`
		Reason     string          `json:"reason"`
	}
	// 응답 뒤 추가 읽기는 하지 않는다. 다음 요청에서 이전 ID 응답을 받으면 중복으로 거부한다.
	if json.Unmarshal(frame, &response) != nil || response.V != 1 || response.ID != id {
		return nil, "", trace.BadParameter("invalid WebAuthn bridge response")
	}
	switch response.Type {
	case "assertion":
		return decodeWebauthnBridgeAssertion(response.Credential)
	case "cancel":
		switch response.Reason {
		case "user_canceled", "invalid_request", "not_associated", "timeout":
			return nil, "", trace.BadParameter("WebAuthn bridge canceled: %s", response.Reason)
		}
	}
	return nil, "", trace.BadParameter("invalid WebAuthn bridge response type or reason")
}

// decodeWebauthnBridgeAssertion은 data의 공통 assertion JSON을 MFA 응답과 빈 사용자명으로 변환한다.
// JSON 형식 오류나 필수 필드 누락을 내용이 없는 오류로 반환한다.
func decodeWebauthnBridgeAssertion(data []byte) (*proto.MFAAuthenticateResponse, string, error) {
	var response wantypes.CredentialAssertionResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, "", trace.BadParameter("invalid browser WebAuthn response")
	}
	if len(response.RawID) == 0 || len(response.AssertionResponse.ClientDataJSON) == 0 || len(response.AssertionResponse.AuthenticatorData) == 0 || len(response.AssertionResponse.Signature) == 0 {
		return nil, "", trace.BadParameter("incomplete browser WebAuthn response")
	}
	return &proto.MFAAuthenticateResponse{
		Response: &proto.MFAAuthenticateResponse_Webauthn{
			Webauthn: wantypes.CredentialAssertionResponseToProto(&response),
		},
	}, "", nil
}
