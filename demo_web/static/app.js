const initialState = JSON.parse(document.body.dataset.initialState || "{}");

const state = {
  snapshot: initialState,
};

const elements = {
  dockerStatus: document.getElementById("docker-status"),
  managerStatus: document.getElementById("manager-status"),
  sessionState: document.getElementById("session-state"),
  sessionId: document.getElementById("session-id"),
  activeMode: document.getElementById("active-mode"),
  eventsCount: document.getElementById("events-count"),
  alertsCount: document.getElementById("alerts-count"),
  latencyValue: document.getElementById("latency-value"),
  sourceEvent: document.getElementById("source-event"),
  commandLog: document.getElementById("command-log"),
  alertSurface: document.getElementById("alert-surface"),
  setupBtn: document.getElementById("setup-btn"),
  resetBtn: document.getElementById("reset-btn"),
  lockbitBtn: document.getElementById("lockbit-btn"),
  safeBtn: document.getElementById("safe-btn"),
  chips: Array.from(document.querySelectorAll(".timeline-chip")),
  timelineModes: Array.from(document.querySelectorAll(".timeline-mode")),
};

function renderSourceEvent(event) {
  if (!event) {
    elements.sourceEvent.innerHTML = '<p class="placeholder">Chưa có sự kiện. Bấm <strong>Thiết lập</strong> rồi chọn một flow demo.</p>';
    return;
  }
  const target = event.target || "-";
  const image = event.image || "-";
  elements.sourceEvent.innerHTML = `
    <div class="kv-list">
      <div class="kv-row"><span>Story step</span><strong>${event.story_title}</strong></div>
      <div class="kv-row"><span>Signal</span><strong>${event.signal_type || "-"}</strong></div>
      <div class="kv-row"><span>Mô tả</span><strong>${event.description || "-"}</strong></div>
      <div class="kv-row"><span>Target</span><code>${target}</code></div>
      <div class="kv-row"><span>Image</span><code>${image}</code></div>
      <div class="kv-row"><span>Thời gian</span><strong>${event.timestamp || "-"}</strong></div>
    </div>
  `;
}

function renderAlert(alert) {
  if (!alert) {
    elements.alertSurface.innerHTML = '<p class="placeholder">Chưa có alert nào được ghi nhận cho session hiện tại.</p>';
    return;
  }
  const mitre = Array.isArray(alert.mitre_ids) && alert.mitre_ids.length ? alert.mitre_ids.join(", ") : "-";
  elements.alertSurface.innerHTML = `
    <div class="kv-list">
      <div class="kv-row"><span>Rule ID</span><strong>${alert.rule_id}</strong></div>
      <div class="kv-row"><span>Mức độ</span><strong>${alert.level}</strong></div>
      <div class="kv-row"><span>Mô tả</span><strong>${alert.description || "-"}</strong></div>
      <div class="kv-row"><span>MITRE</span><strong>${mitre}</strong></div>
      <div class="kv-row"><span>Vị trí</span><code>${alert.location || "-"}</code></div>
      <div class="kv-row"><span>Session</span><code>${alert.demo_session || "-"}</code></div>
    </div>
  `;
  elements.alertSurface.classList.remove("alert-hit");
  void elements.alertSurface.offsetWidth;
  elements.alertSurface.classList.add("alert-hit");
}

function renderCommandLog(lines) {
  elements.commandLog.textContent = (lines || []).join("\n");
}

function setActiveMode(mode) {
  const selected = mode || "lockbit_public";
  elements.activeMode.textContent = selected;
  elements.chips.forEach((chip) => {
    chip.classList.toggle("active", chip.dataset.mode === selected);
  });
  elements.timelineModes.forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.mode !== selected);
  });
}

function renderTimeline(completedSteps) {
  const activeMode = state.snapshot.active_mode || "lockbit_public";
  setActiveMode(activeMode);
  document.querySelectorAll(".timeline-step").forEach((step) => {
    const complete = completedSteps.includes(step.dataset.stepId);
    step.classList.toggle("completed", complete);
  });
}

function flashStep(stepId) {
  if (!stepId) return;
  const currentPanel = document.querySelector(`.timeline-mode[data-mode="${state.snapshot.active_mode || "lockbit_public"}"]`);
  if (!currentPanel) return;
  const step = currentPanel.querySelector(`[data-step-id="${stepId}"]`);
  if (!step) return;
  step.classList.remove("active");
  void step.offsetWidth;
  step.classList.add("active");
}

function applySnapshot(snapshot) {
  state.snapshot = snapshot;
  elements.dockerStatus.textContent = snapshot.services?.docker_up ? "Đang chạy" : "Chưa sẵn sàng";
  elements.managerStatus.textContent = snapshot.services?.manager_configured ? "Đã cấu hình" : "Chưa cấu hình";
  elements.sessionState.textContent = snapshot.state || "idle";
  elements.sessionId.textContent = `session: ${snapshot.session_id || "chưa có"}`;
  elements.eventsCount.textContent = snapshot.replayed_events ?? 0;
  elements.alertsCount.textContent = snapshot.observed_alerts ?? 0;
  elements.latencyValue.textContent = snapshot.first_alert_latency_ms == null ? "-" : `${snapshot.first_alert_latency_ms} ms`;
  renderSourceEvent(snapshot.last_source_event);
  renderAlert(snapshot.last_alert);
  renderCommandLog(snapshot.command_log || []);
  renderTimeline(snapshot.completed_steps || []);
  const busy = snapshot.state === "setting_up" || snapshot.state === "running";
  elements.setupBtn.disabled = busy;
  elements.lockbitBtn.disabled = busy || !snapshot.services?.manager_configured;
  elements.safeBtn.disabled = busy || !snapshot.services?.manager_configured;
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: payload ? JSON.stringify(payload) : null,
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(data.detail || "Request failed");
  }
  const data = await response.json();
  applySnapshot(data.state);
}

elements.setupBtn.addEventListener("click", async () => {
  try {
    await postJson("/api/setup");
  } catch (error) {
    alert(error.message);
  }
});

elements.resetBtn.addEventListener("click", async () => {
  try {
    await postJson("/api/reset");
  } catch (error) {
    alert(error.message);
  }
});

elements.lockbitBtn.addEventListener("click", async () => {
  try {
    await postJson("/api/demo/start", { mode: "lockbit_public", limit: 8, delay: 0.5 });
  } catch (error) {
    alert(error.message);
  }
});

elements.safeBtn.addEventListener("click", async () => {
  try {
    await postJson("/api/demo/start", { mode: "safe_file_activity", limit: 18 });
  } catch (error) {
    alert(error.message);
  }
});

elements.chips.forEach((chip) => {
  chip.addEventListener("click", () => {
    setActiveMode(chip.dataset.mode);
  });
});

const stream = new EventSource("/api/stream");
stream.addEventListener("status", (event) => {
  applySnapshot(JSON.parse(event.data));
});
stream.addEventListener("source_event", (event) => {
  const payload = JSON.parse(event.data);
  renderSourceEvent(payload);
});
stream.addEventListener("alert", (event) => {
  const payload = JSON.parse(event.data);
  renderAlert(payload);
});
stream.addEventListener("metric", (event) => {
  const payload = JSON.parse(event.data);
  elements.eventsCount.textContent = payload.replayed_events ?? 0;
  elements.alertsCount.textContent = payload.observed_alerts ?? 0;
  elements.latencyValue.textContent = payload.first_alert_latency_ms == null ? "-" : `${payload.first_alert_latency_ms} ms`;
});
stream.addEventListener("story_step", (event) => {
  const payload = JSON.parse(event.data);
  flashStep(payload.step_id);
});
stream.addEventListener("command_log", (event) => {
  const payload = JSON.parse(event.data);
  const current = elements.commandLog.textContent ? `${elements.commandLog.textContent}\n` : "";
  elements.commandLog.textContent = `${current}${payload.line}`.trim();
});
stream.addEventListener("error", (event) => {
  const payload = JSON.parse(event.data);
  alert(payload.message);
});

applySnapshot(initialState);
