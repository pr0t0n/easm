export const authStore = {
  get token() {
    return localStorage.getItem("token");
  },
  get me() {
    const raw = localStorage.getItem("me");
    return raw ? JSON.parse(raw) : null;
  },
  setToken(token) {
    localStorage.setItem("token", token);
  },
  setMe(me) {
    localStorage.setItem("me", JSON.stringify(me));
  },
  clear() {
    localStorage.removeItem("token");
    localStorage.removeItem("me");
  },
};
