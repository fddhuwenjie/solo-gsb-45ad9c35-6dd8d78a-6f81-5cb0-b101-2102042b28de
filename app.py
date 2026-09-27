"""跳线盘路由规划器 — Flask 后端。"""

from flask import Flask, jsonify, request, send_from_directory

from audit import audit_signals
from layout import solve_layout
from solver import (EXAMPLES, ConfigError, FaultTargetError,
                    fault_assessment, solve)

app = Flask(__name__, static_folder="static", static_url_path="")


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/examples")
def examples():
    return jsonify({k: v["config"] for k, v in EXAMPLES.items()})


def _structured_error(exc, status):
    """统一的结构化错误响应。"""
    payload = getattr(exc, "payload", None)
    body = {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
    if getattr(exc, "details", None):
        body["error"]["details"] = exc.details
    if payload is not None:
        # NO_ALTERNATIVE：演练本身完成，结构化评估结果随错误一起返回
        body["assessment"] = payload
    return jsonify(body), status


@app.post("/api/plan")
def plan():
    config = request.get_json(force=True, silent=True)
    if not isinstance(config, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "请求体必须是 JSON 配置对象"}}), 400
    try:
        result = solve(config)
    except ConfigError as exc:
        return _structured_error(exc, 400)
    return jsonify(result)


@app.post("/api/panel-layout")
def panel_layout():
    """前面板走线排版：保持规划结论不变，为每根跳线分配槽层与绕行方向。"""
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "请求体必须是 JSON 对象"}}), 400
    config = body.get("config")
    layout = body.get("layout")
    if not isinstance(config, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "缺少 config 配置对象"}}), 400
    if not isinstance(layout, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "缺少 layout 排版对象 {zones: [...]}"}}), 400
    try:
        result = solve_layout(config, layout)
    except ConfigError as exc:
        return _structured_error(exc, 400)
    return jsonify(result)


@app.post("/api/fault-drill")
def fault_drill():
    """单点故障评估：先按当前配置规划，再对选定跳线/常态断路演练。"""
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "请求体必须是 JSON 对象"}}), 400
    config = body.get("config")
    target = body.get("target")
    if not isinstance(config, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "缺少 config 配置对象"}}), 400
    if not isinstance(target, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "缺少 target 断路目标 {type, id}"}}), 400
    try:
        result = fault_assessment(config, target)
    except FaultTargetError as exc:
        # 非法断路目标（跳线不存在 / 常态未生效等）
        return _structured_error(exc, 400)
    except ConfigError as exc:
        if exc.code == "NO_ALTERNATIVE":
            # 演练完成但存在无替代路径的路由：结构化冲突
            return _structured_error(exc, 409)
        return _structured_error(exc, 400)
    return jsonify(result)


@app.post("/api/signal-audit")
def signal_audit():
    """信号命名一致性审计：传播规范名/别名，检测互斥名、别名环、无标签断点、串线。

    审计只读取规划结果，不修改任何路由、常态与跳线。请求体：
      {config: {...规划配置...}, labels: {ports, pairs, cables, routes}}
    """
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "请求体必须是 JSON 对象"}}), 400
    config = body.get("config")
    if not isinstance(config, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "缺少 config 配置对象"}}), 400
    labels = body.get("labels", {})
    if not isinstance(labels, dict):
        return jsonify({"ok": False, "error": {"code": "BAD_REQUEST",
                                               "message": "labels 必须是 JSON 对象"}}), 400
    try:
        result = audit_signals(config, labels)
    except ConfigError as exc:
        return _structured_error(exc, 400)
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
