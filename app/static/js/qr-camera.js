/* UniTrack camera QR scanner. Uses the browser's native BarcodeDetector API.
   Only the authenticated form POST records an access event. */
(() => {
  "use strict";
  const forms = document.querySelectorAll('form[method="POST"], form[method="post"]');
  const form = Array.from(forms).find(item => item.querySelector('textarea[name="qr_text"]'));
  if (!form) return;
  const textArea = form.querySelector('textarea[name="qr_text"]');
  const isSpanish = document.documentElement.lang.toLowerCase().startsWith("es");
  const words = isSpanish ? {
    start: "Escanear con cámara",
    stop: "Detener cámara",
    unavailable: "La cámara QR no está disponible en este navegador. Usa Chrome actualizado o pega el código.",
    insecure: "La cámara requiere HTTPS o localhost.",
    error: "No se pudo abrir la cámara. Revisa los permisos del navegador.",
    scanning: "Apunta la cámara al código QR del usuario.",
    detected: "Código detectado. Verificando..."
  } : {
    start: "Scan with camera",
    stop: "Stop camera",
    unavailable: "Camera QR scanning is unavailable in this browser. Use updated Chrome or paste the code.",
    insecure: "Camera access requires HTTPS or localhost.",
    error: "Could not open the camera. Check your browser permissions.",
    scanning: "Point the camera at the user's QR code.",
    detected: "Code detected. Verifying..."
  };
  const wrap = document.createElement("div");
  wrap.style.cssText = "display:flex;flex-direction:column;align-items:flex-start;gap:10px;margin:12px 0;";
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = words.start;
  button.style.cssText = "background:#5433bf;color:#fff;padding:11px 17px;border:0;border-radius:10px;font-weight:800;cursor:pointer;";
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  status.style.cssText = "font-size:13px;color:#334155;margin:0;";
  const video = document.createElement("video");
  video.autoplay = true;
  video.muted = true;
  video.playsInline = true;
  video.setAttribute("aria-label", isSpanish ? "Vista de la cámara" : "Camera preview");
  video.style.cssText = "display:none;max-width:100%;width:380px;aspect-ratio:4/3;object-fit:cover;border-radius:12px;background:#111827;";
  wrap.append(button, video, status);
  textArea.insertAdjacentElement("afterend", wrap);
  let stream = null;
  let active = false;
  let frame = null;
  let detector = null;
  let pending = false;
  const stop = () => {
    active = false;
    if (frame !== null) cancelAnimationFrame(frame);
    frame = null;
    if (stream) stream.getTracks().forEach(track => track.stop());
    stream = null;
    video.srcObject = null;
    video.style.display = "none";
    button.textContent = words.start;
  };
  const detect = async () => {
    if (!active || pending || !detector) return;
    pending = true;
    try {
      const found = await detector.detect(video);
      if (!active) return;
      if (found.length && typeof found[0].rawValue === "string") {
        const value = found[0].rawValue.trim();
        if (value) {
          textArea.value = value;
          status.textContent = words.detected;
          stop();
          form.requestSubmit();
          return;
        }
      }
    } catch (error) {
      // The camera may still be focusing; keep reading on the next frame.
    } finally {
      pending = false;
      if (active) frame = requestAnimationFrame(detect);
    }
  };
  button.addEventListener("click", async () => {
    if (active) {
      stop();
      return;
    }
    if (!window.isSecureContext) {
      status.textContent = words.insecure;
      return;
    }
    if (!("BarcodeDetector" in window) || !navigator.mediaDevices?.getUserMedia) {
      status.textContent = words.unavailable;
      return;
    }
    button.disabled = true;
    try {
      detector = new BarcodeDetector({formats:["qr_code"]});
      stream = await navigator.mediaDevices.getUserMedia({
        video:{facingMode:{ideal:"environment"}}, audio:false
      });
      video.srcObject = stream;
      await video.play();
      active = true;
      video.style.display = "block";
      button.textContent = words.stop;
      status.textContent = words.scanning;
      frame = requestAnimationFrame(detect);
    } catch (error) {
      stop();
      status.textContent = words.error;
    } finally {
      button.disabled = false;
    }
  });
  window.addEventListener("pagehide", stop);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stop();
  });
})();
