import axios from "axios";

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000",
});

// Injeta o access token em cada requisicao
client.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Trata 401: tenta renovar o access token com o refresh token antes de deslogar.
// Isso evita interrupcoes durante o monitoramento de scans longos (>24h).
let _refreshing = false;
let _refreshQueue = [];

client.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;

    if (error.response?.status === 401 && !original._retry) {
      const refreshToken = localStorage.getItem("refresh_token");

      if (!refreshToken) {
        localStorage.removeItem("token");
        localStorage.removeItem("refresh_token");
        localStorage.removeItem("me");
        window.location.href = "/login";
        return Promise.reject(error);
      }

      if (_refreshing) {
        // Enfileira chamadas que chegaram durante o refresh
        return new Promise((resolve, reject) => {
          _refreshQueue.push({ resolve, reject });
        }).then((token) => {
          original.headers.Authorization = `Bearer ${token}`;
          return client(original);
        });
      }

      original._retry = true;
      _refreshing = true;

      try {
        const { data } = await axios.post(
          `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/api/auth/refresh`,
          { refresh_token: refreshToken }
        );
        localStorage.setItem("token", data.access_token);
        localStorage.setItem("refresh_token", data.refresh_token);

        _refreshQueue.forEach((q) => q.resolve(data.access_token));
        _refreshQueue = [];

        original.headers.Authorization = `Bearer ${data.access_token}`;
        return client(original);
      } catch {
        _refreshQueue.forEach((q) => q.reject(error));
        _refreshQueue = [];
        localStorage.removeItem("token");
        localStorage.removeItem("refresh_token");
        localStorage.removeItem("me");
        window.location.href = "/login";
        return Promise.reject(error);
      } finally {
        _refreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default client;
