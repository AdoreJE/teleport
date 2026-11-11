// Teleport
// Copyright (C) 2026 Gravitational, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/gravitational/teleport/api/utils/prompt"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
)

const bridgeTestCredential = `{"id":"YQ","rawId":"YQ","type":"public-key","response":{"clientDataJSON":"Yg","authenticatorData":"Yw","signature":"ZA"}}`

// bridgeTestChallenge는 테스트에 쓸 유효한 challenge를 반환한다. 인자나 오류는 없다.
func bridgeTestChallenge() *wantypes.CredentialAssertion {
	return &wantypes.CredentialAssertion{Response: wantypes.PublicKeyCredentialRequestOptions{
		Challenge: []byte("challenge"), RelyingPartyID: "teleport.example.com", Timeout: 1000,
	}}
}

// bridgeTestSocket은 t에 정리를 등록하고 상속 FD와 앱 소켓을 반환한다. 소켓 생성 오류는 테스트를 실패시킨다.
func bridgeTestSocket(t *testing.T) (int, net.Conn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	file := os.NewFile(uintptr(fds[1]), "bridge-test")
	peer, err := net.FileConn(file)
	require.NoError(t, file.Close())
	require.NoError(t, err)
	t.Cleanup(func() { peer.Close() })
	return fds[0], peer
}

// bridgeTestRequest는 reader에서 요청 프레임을 읽어 반환한다. 읽기나 JSON 오류는 error로 반환한다.
func bridgeTestRequest(reader *bufio.Reader) (map[string]json.RawMessage, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var frame map[string]json.RawMessage
	err = json.Unmarshal(line, &frame)
	return frame, err
}

// TestWebauthnBridgeResponses는 t로 정상 및 잘못된 응답을 검증한다. 실패는 테스트로 보고한다.
func TestWebauthnBridgeResponses(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		ok             bool
	}{
		{"assertion", `{"v":1,"type":"assertion","id":%s,"credential":` + bridgeTestCredential + `}`, true},
		{"cancel-user", `{"v":1,"type":"cancel","id":%s,"reason":"user_canceled"}`, false},
		{"cancel-invalid", `{"v":1,"type":"cancel","id":%s,"reason":"invalid_request"}`, false},
		{"cancel-association", `{"v":1,"type":"cancel","id":%s,"reason":"not_associated"}`, false},
		{"cancel-timeout", `{"v":1,"type":"cancel","id":%s,"reason":"timeout"}`, false},
		{"invalid-cancel", `{"v":1,"type":"cancel","id":%s,"reason":"secret-payload"}`, false},
		{"EOF", "", false},
		{"malformed", `{"id":%s,`, false},
		{"wrong-ID", `{"v":1,"type":"assertion","ignored":%s,"id":"other","credential":` + bridgeTestCredential + `}`, false},
		{"unknown-type", `{"v":1,"type":"secret-payload","id":%s}`, false},
		{"handshake-mismatch", `{"v":1,"type":"hello","id":%s,"protocol":"wrong","rev":2}`, false},
		{"version-mismatch", `{"v":2,"type":"assertion","id":%s,"credential":` + bridgeTestCredential + `}`, false},
		{"incomplete-credential", `{"v":1,"type":"assertion","id":%s,"credential":{}}`, false},
		{"invalid-credential", `{"v":1,"type":"assertion","id":%s,"credential":"secret-payload"}`, false},
		{"oversized", `{"id":%s,"padding":"` + strings.Repeat("x", webauthnBridgeFrameLimit) + `"}`, false},
		{"trailing-JSON", `{"v":1,"type":"assertion","id":%s,"credential":` + bridgeTestCredential + `} {}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, peer := bridgeTestSocket(t)
			t.Setenv("TSH_WEBAUTHN_BRIDGE_FD", strconv.Itoa(fd))
			done := make(chan error, 1)
			go func() {
				defer peer.Close()
				reader := bufio.NewReader(peer)
				hello, err := bridgeTestRequest(reader)
				if err != nil {
					done <- err
					return
				}
				if string(hello["v"]) != "1" || string(hello["type"]) != `"hello"` || string(hello["protocol"]) != `"tsh-webauthn-bridge"` || string(hello["rev"]) != "1" {
					done <- fmt.Errorf("invalid hello")
					return
				}
				request, err := bridgeTestRequest(reader)
				if err != nil {
					done <- err
					return
				}
				var id string
				if err := json.Unmarshal(request["id"], &id); err != nil {
					done <- err
					return
				}
				if _, err := uuid.Parse(id); err != nil {
					done <- err
					return
				}
				expected, _ := json.Marshal(bridgeTestChallenge().Response)
				if string(request["type"]) != `"assert"` || !bytes.Equal(request["publicKey"], expected) {
					done <- fmt.Errorf("invalid request")
					return
				}
				if tc.response != "" {
					_, err = fmt.Fprintf(peer, tc.response+"\n", request["id"])
				}
				// 크기 초과 시 수신자가 먼저 닫아 송신 오류가 생길 수 있다.
				if tc.name == "oversized" {
					err = nil
				}
				done <- err
			}()
			var stderr bytes.Buffer
			login := browserPasswordlessLogin(&stderr, prompt.NewFakeReader())
			got, _, err := login(t.Context(), "", bridgeTestChallenge(), nil, nil)
			if tc.ok {
				require.NoError(t, err)
				require.NotNil(t, got.GetWebauthn())
				require.Equal(t, []byte("a"), got.GetWebauthn().GetRawId())
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "secret-payload")
			}
			require.Empty(t, stderr.String())
			require.NoError(t, <-done)
		})
	}
}

// TestWebauthnBridgeDuplicateはtで次の要求中の前ID応答を拒否することを検証する。
func TestWebauthnBridgeDuplicate(t *testing.T) {
	fd, peer := bridgeTestSocket(t)
	done := make(chan error, 1)
	go func() {
		defer peer.Close()
		reader := bufio.NewReader(peer)
		if _, err := bridgeTestRequest(reader); err != nil {
			done <- err
			return
		}
		first, err := bridgeTestRequest(reader)
		if err != nil {
			done <- err
			return
		}
		response := fmt.Sprintf(`{"v":1,"type":"assertion","id":%s,"credential":%s}`+"\n", first["id"], bridgeTestCredential)
		if _, err := io.WriteString(peer, response); err != nil {
			done <- err
			return
		}
		if _, err := bridgeTestRequest(reader); err != nil {
			done <- err
			return
		}
		_, err = io.WriteString(peer, response)
		done <- err
	}()
	login := newWebauthnBridgeLogin(strconv.Itoa(fd))
	_, _, err := login(t.Context(), "", bridgeTestChallenge(), nil, nil)
	require.NoError(t, err)
	_, _, err = login(t.Context(), "", bridgeTestChallenge(), nil, nil)
	require.Error(t, err)
	require.NoError(t, <-done)
}

// TestWebauthnBridgeInvalidFDはtで不正・閉鎖・標準入出力FDからの強制失敗を検証する。
func TestWebauthnBridgeInvalidFD(t *testing.T) {
	for _, fd := range []string{"", "abc", "-1", "0", "1", "2", "99999999999999999999999999", "999999"} {
		t.Run(fd, func(t *testing.T) {
			t.Setenv("TSH_WEBAUTHN_BRIDGE_FD", fd)
			var stderr bytes.Buffer
			_, _, err := browserPasswordlessLogin(&stderr, prompt.NewFakeReader())(t.Context(), "", bridgeTestChallenge(), nil, nil)
			require.Error(t, err)
			require.Empty(t, stderr.String())
		})
	}
}

// TestWebauthnBridgeTimeoutはtで短い要求timeoutとcontextキャンセルによる読み取り中断を検証する。
func TestWebauthnBridgeTimeout(t *testing.T) {
	for _, mode := range []string{"request", "context", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			fd, peer := bridgeTestSocket(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			assertion := bridgeTestChallenge()
			if mode == "request" {
				assertion.Response.Timeout = 30
			}
			if mode == "context" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer deadlineCancel()
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				reader := bufio.NewReader(peer)
				bridgeTestRequest(reader)
				bridgeTestRequest(reader)
				if mode == "cancel" {
					cancel()
				}
			}()
			start := time.Now()
			_, _, err := newWebauthnBridgeLogin(strconv.Itoa(fd))(ctx, "", assertion, nil, nil)
			require.Error(t, err)
			require.Less(t, time.Since(start), time.Second)
			peer.Close()
			<-done
		})
	}
}

// TestWebauthnBridgeCloseOnExec는t로 초기 FD와 복제 연결의 CLOEXEC 플래그를 검증한다.
func TestWebauthnBridgeCloseOnExec(t *testing.T) {
	fd, _ := bridgeTestSocket(t)
	b := &webauthnBridge{fd: strconv.Itoa(fd)}
	require.NoError(t, b.open())
	defer b.conn.Close()
	raw, err := b.conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}).SyscallConn()
	require.NoError(t, err)
	var flags int
	require.NoError(t, raw.Control(func(fd uintptr) { flags, err = unix.FcntlInt(fd, unix.F_GETFD, 0) }))
	require.NoError(t, err)
	require.NotZero(t, flags&unix.FD_CLOEXEC)
}

// TestWebauthnBridgeFrameBoundary는 t로 송신 프레임의 정확한 상한과 초과 거부를 검증한다.
func TestWebauthnBridgeFrameBoundary(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	b := &webauthnBridge{conn: local}
	done := make(chan int, 1)
	go func() {
		frame, _ := bufio.NewReaderSize(peer, webauthnBridgeFrameLimit).ReadSlice('\n')
		done <- len(frame)
	}()
	require.NoError(t, b.write(strings.Repeat("x", webauthnBridgeFrameLimit-3)))
	require.Equal(t, webauthnBridgeFrameLimit, <-done)
	require.Error(t, b.write(strings.Repeat("x", webauthnBridgeFrameLimit-2)))
	peer.Close()
	require.Error(t, b.write("closed"))
}

// TestWebauthnBridgeNonSocket는 t로 파일 FD를 거부하고 마커로 강등하지 않는지 검증한다.
func TestWebauthnBridgeNonSocket(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "bridge")
	require.NoError(t, err)
	fd, err := unix.Dup(int(file.Fd()))
	require.NoError(t, err)
	require.NoError(t, file.Close())
	_, _, err = newWebauthnBridgeLogin(strconv.Itoa(fd))(t.Context(), "", bridgeTestChallenge(), nil, nil)
	require.Error(t, err)
}

// TestWebauthnBridgeFailedConnection는 t로 실패한 브리지 재사용과 잘못된 challenge를 거부하는지 검증한다.
func TestWebauthnBridgeFailedConnection(t *testing.T) {
	login := newWebauthnBridgeLogin("invalid")
	_, _, err := login(t.Context(), "", nil, nil, nil)
	require.Error(t, err)
	_, _, err = login(t.Context(), "", bridgeTestChallenge(), nil, nil)
	require.ErrorContains(t, err, "already failed")
}
