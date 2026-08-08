const views = {
  login: document.querySelector("#view-login"),
  register: document.querySelector("#view-register"),
  recovery: document.querySelector("#view-recovery"),
};
const tabs = document.querySelectorAll(".tab[data-view]");
const viewTitle = document.querySelector("#view-title");
const viewSubtitle = document.querySelector("#view-subtitle");
const result = document.querySelector(".result");
const resultTitle = document.querySelector("#result-title");
const resultMessage = document.querySelector("#result");

const viewCopy = {
  login: ["Welcome back", "Sign in to continue to your account."],
  register: ["Create your account", "Welcome. Please fill in the details to get started."],
  recovery: ["Recover your password", "We will help you get back into your account."],
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

function setResult(title, message, state = "") {
  resultTitle.textContent = title;
  resultMessage.textContent = message;
  result.dataset.state = state;
}

async function submitForm(event, path) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  const label = button.querySelector(".button-label");

  if (button.disabled) return;

  button.disabled = true;
  label.textContent = "Working...";
  setResult("Request in progress", "The Rust server is processing your request.", "pending");

  try {
    const data = Object.fromEntries(new FormData(form));
    const response = await fetch(`/api/auth/${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(data),
    });
    const body = await response.text();
    setResult(
      response.ok ? "Request succeeded" : "Request was rejected",
      `${response.status} ${response.statusText}\n${body}`,
      response.ok ? "success" : "error",
    );
  } catch (error) {
    setResult("Request failed", String(error), "error");
  } finally {
    button.disabled = false;
    label.textContent = button.dataset.defaultLabel;
  }
}

document.querySelectorAll(".tab[data-view], [data-view='recovery'], [data-view='login']").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

document.querySelector("#login").addEventListener("submit", (event) =>
  submitForm(event, "sign-in/email"));
document.querySelector("#register").addEventListener("submit", (event) =>
  submitForm(event, "sign-up/email"));
document.querySelector("#request-recovery").addEventListener("submit", (event) =>
  submitForm(event, "request-password-reset"));
document.querySelector("#reset-password").addEventListener("submit", (event) =>
  submitForm(event, "reset-password"));

document.querySelectorAll("button[type=submit]").forEach((button) => {
  button.dataset.defaultLabel = button.querySelector(".button-label").textContent;
});

showView("login");
