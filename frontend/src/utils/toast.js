export function emitToast(type, message) {
  window.dispatchEvent(
    new CustomEvent("app:toast", {
      detail: {
        type: type || "info",
        message: String(message || ""),
      },
    })
  );
}

export function toastError(message) {
  emitToast("error", message);
}

export function toastSuccess(message) {
  emitToast("success", message);
}
