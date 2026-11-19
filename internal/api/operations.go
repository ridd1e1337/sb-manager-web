package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ridd1e1337/sb-manager-web/internal/runner"
	"github.com/ridd1e1337/sb-manager-web/internal/types"
)

func (s *Server) operationsAPI(w http.ResponseWriter, r *http.Request, session types.Session) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"operations": runner.Operations(), "role": s.auth.Role(session.Username)})
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "只支持 GET、POST", nil)
		return
	}
	var request struct {
		ServerID       string         `json:"server_id"`
		Action         string         `json:"action"`
		Args           map[string]any `json:"args"`
		IdempotencyKey string         `json:"idempotency_key"`
	}
	if err := decodeBody(r, &request); err != nil {
		writeError(w, 400, "VALIDATION_FAILED", err.Error(), nil)
		return
	}
	op, ok := runner.LookupOperation(request.Action)
	if !ok {
		writeError(w, 400, "VALIDATION_FAILED", "未列入运维操作白名单", nil)
		return
	}
	role := s.auth.Role(session.Username)
	if (op.AdminOnly && role != "admin") || (!op.ReadOnly && role == "viewer") {
		writeError(w, 403, "ROLE_FORBIDDEN", "当前账号不能执行此操作", nil)
		return
	}
	if request.ServerID == "" {
		request.ServerID = types.ServerLocal
	}
	if request.Args == nil {
		request.Args = map[string]any{}
	}
	s.enqueueAction(w, request.ServerID, actionRequest{Action: request.Action, Args: request.Args, IdempotencyKey: request.IdempotencyKey}, session)
}

var managerVersionPattern = regexp.MustCompile(`(?:^|\s)v?(\d+)\.(\d+)\.(\d+)(?:-alpha\.(\d+))?(?:\s|$)`)

func managerSupports(version string, alpha int) bool {
	if alpha == 0 {
		return true
	}
	m := managerVersionPattern.FindStringSubmatch(version)
	if len(m) == 0 {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	a, _ := strconv.Atoi(m[4])
	return major > 0 || minor > 1 || (minor == 1 && (patch > 0 || m[4] == "" || a >= alpha))
}
func (s *Server) operationCompatibility(server types.Server, op runner.Operation) error {
	version := server.SBManagerVersion
	if server.ID == types.ServerLocal {
		if op.MinAlpha == 0 {
			return nil
		}
		result, err := s.runLocal("manager.version", nil)
		if err != nil {
			return errors.New("无法读取本机 sb-manager 版本，请检查安装与 helper 状态")
		}
		version = strings.TrimSpace(result.Stdout)
	} else {
		if !server.Online || time.Since(server.LastSeen) > 2*time.Minute {
			return errors.New("目标 Agent 离线，请等待心跳恢复")
		}
		supported := false
		for _, feature := range server.AgentFeatures {
			if feature == "operations_v2" {
				supported = true
			}
		}
		if !supported {
			return errors.New("请先更新目标 Agent，再使用新版运维功能")
		}
	}
	if !managerSupports(version, op.MinAlpha) {
		return errors.New("目标 sb-manager 版本过旧或未知，请先更新至 alpha." + strconv.Itoa(op.MinAlpha) + " 或更新版本")
	}
	return nil
}

func (s *Server) taskArguments(task types.Task) (map[string]any, error) {
	if !task.Private {
		return task.Args, nil
	}
	data, err := s.store.TaskSecret(task.ID, "args", false)
	if err != nil {
		return nil, err
	}
	var args map[string]any
	err = json.Unmarshal(data, &args)
	return args, err
}

func (s *Server) privateTaskResult(w http.ResponseWriter, r *http.Request, session types.Session, task types.Task) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "使用 POST 领取私有结果", nil)
		return
	}
	if s.auth.Role(session.Username) != "admin" {
		writeError(w, 403, "ROLE_FORBIDDEN", "只有管理员可读取私有结果", nil)
		return
	}
	if !task.Private || task.Status == types.TaskPending || task.Status == types.TaskRunning {
		writeError(w, 409, "RESULT_UNAVAILABLE", "私有结果尚未生成", nil)
		return
	}
	data, err := s.store.TaskSecret(task.ID, "result", true)
	if err != nil {
		writeError(w, 410, "RESULT_EXPIRED", "结果已领取或超过 15 分钟，请重新执行查询；动态订阅可按 ID 撤销后重新创建", nil)
		return
	}
	s.recordAudit(session.Username, "task.private-result", []string{task.ServerID}, []string{task.ID}, "read")
	var result map[string]any
	if json.Unmarshal(data, &result) != nil {
		writeError(w, 500, "STORAGE_ERROR", "私有结果无法解析", nil)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) protectTaskResult(task types.Task, output, problem string) (string, string, error) {
	if !task.Private {
		return truncate(redact(output), 32768), truncate(redact(problem), 8192), nil
	}
	data, err := json.Marshal(map[string]string{"output": truncate(output, 65536), "error": truncate(problem, 8192)})
	if err == nil {
		err = s.store.PutTaskSecret(task.ID, "result", data, time.Now().Add(15*time.Minute))
	}
	if err != nil {
		return "", "无法保存私有结果", err
	}
	publicError := ""
	if problem != "" {
		publicError = "执行失败；请领取私有结果查看详情"
	}
	return "私有结果已加密保存，请在 15 分钟内领取。", publicError, nil
}
