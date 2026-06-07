// globals (yay vanilla javascript ftw)
setLoginState(null);
fetchBlogs();
refreshCsrfToken();
loginCheck();
document.getElementById("login-form")
    .addEventListener("submit", onLoginSubmit);
document.getElementById("logout-form")
    .addEventListener("submit", onLogoutSubmit);
document.getElementById("blog-form")
    .addEventListener("submit", onBlogSubmit);
let devToast = new bootstrap.Toast(
    document.getElementById("devToast"),
    { delay: 10000 }
);

function onLoginSubmit(event) {
  const username = event.target[0].value;
  const password = event.target[1].value;
  const rememberMe = event.target.elements["remember-me"].checked;
  const formData = new URLSearchParams({username, password});
  if (rememberMe) {
    formData.set("remember-me", "on");
  }
  event.preventDefault();
  refreshCsrfToken()
      .then(() => fetch("/login", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-XSRF-TOKEN": getXsrfToken(),
    },
    body: formData,
  }))
      .then(filterOk)
      .then(response => response.json())
      .then(user => setLoginState(user))
      .then(() => event.target.reset());
}

function onLogoutSubmit(event) {
  event.preventDefault();
  fetch("/logout", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "X-XSRF-TOKEN": getXsrfToken(),
    },
  })
      .then(filterOk)
      .then(() => refreshCsrfToken())
      .then(() => setLoginState(null));
}

function onBlogSubmit(event) {
  const data = {"title": event.target[0].value, "body": event.target[1].value};
  event.preventDefault();
  fetch("/api/blog", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-XSRF-TOKEN": getXsrfToken(),
    },
    body: JSON.stringify(data),
  })
      .then(filterOk)
      .then(() => fetchBlogs())
      .then(() => event.target.reset());
}

// switch display based on login status
function loginCheck() {
  fetch("/api/user/whoami", {
    credentials: "same-origin",
  })
      .then(response => {
        if (response.status === 401 || response.status === 403) {
          return null;
        }
        return filterOk(response).then(response => response.json());
      })
      .then(user => setLoginState(user));
}

function setLoginState(user) {
  const authentic = user !== null;
  document.getElementById("login-form").parentElement.hidden = authentic;
  document.getElementById("logout-form").parentElement.hidden = !authentic;
  document.getElementById("blog-form").parentElement.hidden = !authentic;
  document.getElementById("username").innerText = authentic ? user.fullname : "anonymous";
}

function fetchBlogs() {
  fetch("/api/blog", {
    credentials: "same-origin",
  })
      .then(filterOk)
      .then(response => response.json())
      .then(page => renderBlogs(page.content));
}

function getXsrfToken() {
  // Der XSRF-TOKEN Cookie wird von Spring Security fuer diese Origin gesetzt.
  // Man sendet ihn als X-XSRF-TOKEN Header zurueck und der Abgleich verhindert dann eben das CSRF.
  const token = document.cookie
      .split("; ")
      .find(cookie => cookie.startsWith("XSRF-TOKEN="))
      ?.split("=")[1];
  return token ? decodeURIComponent(token) : "";
}

function refreshCsrfToken() {
  // Dieser Endpoint erzeugt bewusst nur einen neuen CSRF-Cookie und gibt keine sensiblen Daten aus.
  return fetch("/api/user/csrf", {
    credentials: "same-origin",
  }).then(filterOk);
}

function renderBlogs(blogs) {
  const blogDiv = document.getElementById("blog-container");
  blogDiv.replaceChildren();
  for (const blog of blogs) {
    const title = document.createElement("h2");
    title.textContent = blog.title;

    const createdAt = document.createElement("p");
    createdAt.textContent = blog.createdAt;

    const body = document.createElement("p");
    body.textContent = blog.body;

    blogDiv.append(title, createdAt, body);
  }
}

function showDevError(message) {
  document.getElementById("devToastText").textContent = message;
  devToast.show();
}

function filterOk(response) {
  if (response.ok) {
    return response;
  }
  return response.text().then(function() {
    let msg = `HTTP ${response.status} ${response.statusText}`;
    if (response.status === 429) {
      msg += "\nZu viele Loginversuche. Bitte spaeter erneut versuchen.";
    }
    showDevError(msg);
    throw response;
  });
}
