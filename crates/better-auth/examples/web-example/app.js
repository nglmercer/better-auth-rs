const resultCard = document.querySelector(".result-card");
const resultTitle = document.querySelector("#result-title");
const result = document.querySelector("#result");

function setResult(title, message, state) {
  resultTitle.textContent = title;
  result.textContent = message;
  resultCard.dataset.state = state;
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
    label.textContent = path === "sign-up/email" ? "Register" : "Login";
  }
}

document.querySelector("#register").addEventListener("submit", (event) =>
  submitForm(event, "sign-up/email"));
document.querySelector("#login").addEventListener("submit", (event) =>
  submitForm(event, "sign-in/email"));
