const views = {
  login: document.querySelector("#view-login"),
  register: document.querySelector("#view-register"),
};
const tabs = document.querySelectorAll(".tab[data-view]");
const recoveryModal = document.querySelector("#recovery-modal");
const recoverySteps = document.querySelectorAll("[data-recovery-step]");
const progressDots = document.querySelectorAll("[data-progress]");
const viewTitle = document.querySelector("#view-title");
const viewSubtitle = document.querySelector("#view-subtitle");
const mainResult = document.querySelector(".auth-card > .result");
const modalResult = recoveryModal.querySelector(".result");
const recoveryEmail = document.querySelector("#recovery-email");
const requestRecovery = document.querySelector("#request-recovery");
const verifyRecovery = document.querySelector("#verify-recovery");
const resetPassword = document.querySelector("#reset-password");
let recoveryToken = "";

const viewCopy = {
  login: ["Welcome back", "Sign in to continue to your account."],
  register: ["Create your account", "Welcome. Please fill in the details to get started."],
};

function showView(name) {
  Object.entries(views).forEach(([viewName, element]) => {
    element.hidden = viewName !== name;
  });

  tabs.forEach((tab) => {
    const active = tab.dataset.view === name;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });

  [viewTitle.textContent, viewSubtitle.textContent] = viewCopy[name];
}

function setResult(target, title, message, state = "") {
  target.querySelector(".result-title").textContent = title;
  target.querySelector(".result-message").textContent = message;
  target.dataset.state = state;
}

function resultFor(form) {
  return form.closest(".modal-card")?.querySelector(".result") ?? mainResult;
}

function showRecoveryStep(step) {
  recoverySteps.forEach((element) => {
    element.hidden = Number(element.dataset.recoveryStep) !== step;
  });
  progressDots.forEach((dot) => {
    dot.classList.toggle("is-active", Number(dot.dataset.progress) <= step);
  });
}

function resetRecovery() {
  recoveryToken = "";
  requestRecovery.reset();
  verifyRecovery.reset();
  resetPassword.reset();
  setResult(modalResult, "Ready when you are", "Your recovery result will appear here.");
  showRecoveryStep(1);
}

async function submitForm(event, path, onSuccess) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  const label = button.querySelector(".button-label");
  const result = resultFor(form);

  if (button.disabled) return;

  button.disabled = true;
  label.textContent = "Working...";
  setResult(result, "Request in progress", "The Rust server is processing your request.", "pending");

  try {
    const data = Object.fromEntries(new FormData(form));
    delete data.confirm_password;
    const response = await fetch(`/api/auth/${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(data),
    });
    const body = await response.text();
    setResult(
      result,
      response.ok ? "Request succeeded" : "Request was rejected",
      `${response.status} ${response.statusText}\n${body}`,
      response.ok ? "success" : "error",
    );
    if (response.ok && onSuccess) onSuccess(body);
  } catch (error) {
    setResult(result, "Request failed", String(error), "error");
  } finally {
    button.disabled = false;
    label.textContent = button.dataset.defaultLabel;
  }
}

document.querySelectorAll(".tab[data-view]").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

document.querySelector("[data-open-recovery]").addEventListener("click", () => {
  resetRecovery();
  recoveryModal.showModal();
});

document.querySelectorAll("[data-close-recovery]").forEach((button) => {
  button.addEventListener("click", () => recoveryModal.close());
});

recoveryModal.addEventListener("click", (event) => {
  if (event.target === recoveryModal) recoveryModal.close();
});
recoveryModal.addEventListener("close", resetRecovery);

document.querySelectorAll("[data-recovery-step-link]").forEach((button) => {
  button.addEventListener("click", () => showRecoveryStep(Number(button.dataset.recoveryStepLink)));
});

document.querySelector("#login").addEventListener("submit", (event) =>
  submitForm(event, "sign-in/email"));
document.querySelector("#register").addEventListener("submit", (event) =>
  submitForm(event, "sign-up/email"));
requestRecovery.addEventListener("submit", (event) => {
  const email = requestRecovery.elements.email.value;
  submitForm(event, "request-password-reset", () => {
    recoveryEmail.textContent = email;
    setResult(modalResult, "Check your inbox", "Paste the recovery token to continue.", "success");
    showRecoveryStep(2);
  });
});
verifyRecovery.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!verifyRecovery.reportValidity()) return;
  recoveryToken = verifyRecovery.elements.token.value.trim();
  resetPassword.elements.token.value = recoveryToken;
  setResult(modalResult, "Token verified", "Now choose a new password.", "success");
  showRecoveryStep(3);
});
resetPassword.addEventListener("submit", (event) => {
  if (resetPassword.elements.new_password.value !== resetPassword.elements.confirm_password.value) {
    event.preventDefault();
    setResult(modalResult, "Passwords do not match", "Enter the same password in both fields.", "error");
    return;
  }
  submitForm(event, "reset-password", (body) => {
    const reset = body.includes('"reset":true');
    setResult(
      modalResult,
      reset ? "Password updated" : "Recovery token not accepted",
      reset ? "You can now close this dialog and sign in." : "Request a new token and try again.",
      reset ? "success" : "error",
    );
  });
});

document.querySelectorAll("button[type=submit]").forEach((button) => {
  button.dataset.defaultLabel = button.querySelector(".button-label").textContent;
});

showView("login");
