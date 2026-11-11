/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/stretchr/testify/require"
)

// TestFluxHiddenFlags는 t로 SSH 도움말을 실행하고 flux 숨김 플래그가 노출되지 않는지 검증한다.
func TestFluxHiddenFlags(t *testing.T) {
	for _, args := range [][]string{{"ssh", "--help"}, {"help", "ssh"}} {
		output := fluxCommandOutput(t, args...)
		require.Contains(t, output, "--port")
		require.NotContains(t, strings.ToLower(output), "flux")
	}
}

// TestFluxFlagParsing은 t로 host 전후의 소켓 플래그를 파싱하고 접속 전에 설정을 검증한다.
func TestFluxFlagParsing(t *testing.T) {
	t.Setenv("TELEPORT_HOME", t.TempDir())
	t.Setenv("TELEPORT_TOOLS_VERSION", "off")
	for _, beforeHost := range []bool{true, false} {
		t.Run(fmt.Sprintf("before_host=%t", beforeHost), func(t *testing.T) {
			flags := []string{"--flux-sftp-socket=/a", "--flux-control-socket=/b"}
			args := []string{"ssh", "user@host"}
			if beforeHost {
				args = append(append([]string{"ssh"}, flags...), "user@host")
			} else {
				args = append(args, flags...)
			}
			stopped := errors.New("파싱 검증 완료")
			err := Run(context.Background(), args, func(cf *CLIConf) error {
				if beforeHost {
					require.Equal(t, "/a", cf.FluxSFTPSocket)
					require.Equal(t, "/b", cf.FluxControlSocket)
					require.Empty(t, cf.RemoteCommand)
				} else {
					require.Empty(t, cf.FluxSFTPSocket)
					require.Empty(t, cf.FluxControlSocket)
					require.Equal(t, flags, cf.RemoteCommand)
				}
				return stopped
			})
			require.ErrorIs(t, err, stopped)
		})
	}
}

// TestFluxVersion은 t로 client 전용 표식과 일반 버전 출력의 표식 부재를 검증한다.
func TestFluxVersion(t *testing.T) {
	for _, format := range []string{"text", "json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			args := []string{"version"}
			if format != "text" {
				args = append(args, "--format="+format)
			}
			ordinary := fluxCommandOutput(t, args...)
			client := fluxCommandOutput(t, append(args, "--client")...)
			require.NotContains(t, ordinary, "flux-sftp-bridge")
			if format == "text" {
				require.Equal(t, ordinary+"flux-sftp-bridge: 1\n", client)
				return
			}
			data := []byte(client)
			if format == "yaml" {
				var err error
				data, err = yaml.YAMLToJSON(data)
				require.NoError(t, err)
			}
			var version map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(data, &version))
			var bridge int
			require.NoError(t, json.Unmarshal(version["flux-sftp-bridge"], &bridge))
			require.Equal(t, 1, bridge)
		})
	}
}

// fluxCommandOutput은 t와 args로 테스트 실행 파일에서 tsh를 실행하고 stdout·stderr 문자열을 반환한다.
// 빈 TELEPORT_HOME과 업데이트 비활성화로 프로필 조회에 따른 네트워크 접속을 방지하며 실행 오류는 테스트를 실패시킨다.
func fluxCommandOutput(t *testing.T, args ...string) string {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.CommandContext(context.Background(), executable, args...)
	cmd.Env = []string{
		fmt.Sprintf("%s=1", tshBinMainTestEnv),
		"TELEPORT_TOOLS_VERSION=off",
		"TELEPORT_HOME=" + t.TempDir(),
	}
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
	return string(output)
}
