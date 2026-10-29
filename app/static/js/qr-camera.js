/* UniTrack camera QR reader. Local jsQR library avoids browser-specific native QR APIs.
 * Camera access requires HTTPS or localhost. Never automatically register access. */
(() => {
  "use strict";

  const init = () => {
    const widget = document.getElementById("unitrackQrCamera");
    if (!widget) return;
    const form = widget.closest("form");
    const field = form?.querySelector('[name="qr_text"]');
    if (!form || !field) return;

    const startButton = widget.querySelector("[data-qr-start]");
    const stopButton = widget.querySelector("[data-qr-stop]");
    const photoButton = widget.querySelector("[data-qr-photo]");
    const video = widget.querySelector("[data-qr-video]");
    const status = widget.querySelector("[data-qr-status]");
    const cameraChoice = widget.querySelector("[data-qr-camera-choice]");
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d", { willReadFrequently: true });
    const spanish = document.documentElement.lang.toLowerCase().startsWith("es");
    const messages = spanish ? {
      start: "Escanear con cámara", stop: "Detener cámara",
      help: "La cámara requiere HTTPS o localhost.",
      unsupported: "Este navegador no permite acceder a la cámara. Puedes escanear una imagen.",
      library: "No se pudo cargar el lector QR. Actualiza la página.",
      request: "Solicitando permiso para usar la cámara...",
      ready: "Apunta la cámara hacia un código QR válido.",
      noCamera: "No hay una cámara disponible. Usa una imagen QR.",
      denied: "Permiso de cámara denegado. Permite el acceso desde el icono de la cámara del navegador.",
      busy: "Otra aplicación está usando la cámara. Ciérrala e inténtalo de nuevo.",
      error: "No se pudo iniciar la cámara. Revisa la configuración del navegador.",
      detected: "Código detectado. Revisa el contenido y pulsa «Escanear QR» para confirmar.",
      imageError: "No se pudo leer la imagen seleccionada.",
      imageMissing: "No se detectó un código QR en esta imagen.",
      selectCamera: "Seleccionar cámara"
    } : {
      start: "Scan with camera", stop: "Stop camera",
      help: "Camera access requires HTTPS or localhost.",
      unsupported: "This browser cannot access the camera. You can scan an image instead.",
      library: "QR decoder could not load. Refresh the page.",
      request: "Requesting camera permission...",
      ready: "Point the camera at a valid QR code.",
      noCamera: "No camera was found. Use a QR image instead.",
      denied: "Camera permission denied. Allow access in your browser's camera settings.",
      busy: "Another application is using the camera. Close it and try again.",
      error: "Could not start the camera. Check browser settings.",
      detected: "QR found. Review the code and click Scan QR to confirm.",
      imageError: "Could not read the selected image.",
      imageMissing: "No QR code was detected in this image.",
      selectCamera: "Select camera"
    };

    let stream = null;
    let scanning = false;
    let timeoutId = null;
    let inFlight = false;
    let lastDevice = "";

    const announce = (message) => { status.textContent = message; };

    const stop = () => {
      scanning = false;
      if (timeoutId !== null) window.clearTimeout(timeoutId);
      timeoutId = null;
      if (stream) stream.getTracks().forEach((track) => track.stop());
      stream = null;
      video.pause();
      video.srcObject = null;
      video.hidden = true;
      startButton.hidden = false;
      stopButton.hidden = true;
      startButton.disabled = false;
    };

    const drawFrame = (source, naturalWidth, naturalHeight) => {
      if (!context || !naturalWidth || !naturalHeight) return null;
      const factor = Math.min(1, 960 / Math.max(naturalWidth, naturalHeight));
      canvas.width = Math.max(1, Math.floor(naturalWidth * factor));
      canvas.height = Math.max(1, Math.floor(naturalHeight * factor));
      context.drawImage(source, 0, 0, canvas.width, canvas.height);
      const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
      return window.jsQR(pixels.data, pixels.width, pixels.height, {
        inversionAttempts: "attemptBoth"
      });
    };

    const foundQr = (value, automatic = false) => {
      if (!value || !value.trim()) return;
      field.value = value.trim();
      stop();
      field.focus();
      announce(messages.detected);
      // An authorized operator has deliberately started the camera.
      // Successful detection now submits the existing CSRF-protected form
      // automatically, recording one entry or exit. File uploads still
      // require explicit confirmation.
      if (automatic) {
        const submit = form.querySelector('button[type="submit"]');
        if (typeof form.requestSubmit === "function") form.requestSubmit(submit || undefined);
        else if (submit) submit.click();
      }
    };

    const tick = () => {
      if (!scanning || inFlight) return;
      inFlight = true;
      try {
        if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
          const result = drawFrame(video, video.videoWidth, video.videoHeight);
          if (result?.data) {
            foundQr(result.data, true);
            return;
          }
        }
      } catch (_) {
        // Frames can occasionally be unavailable while focusing the camera.
      } finally {
        inFlight = false;
        if (scanning) timeoutId = window.setTimeout(tick, 160);
      }
    };

    const listCameras = async () => {
      if (!navigator.mediaDevices?.enumerateDevices) return;
      try {
        const devices = (await navigator.mediaDevices.enumerateDevices())
          .filter((device) => device.kind === "videoinput");
        cameraChoice.replaceChildren();
        if (devices.length < 2) {
          cameraChoice.hidden = true;
          return;
        }
        devices.forEach((device, i) => {
          const option = document.createElement("option");
          option.value = device.deviceId;
          option.textContent = device.label || `${messages.selectCamera} ${i + 1}`;
          cameraChoice.appendChild(option);
        });
        cameraChoice.hidden = false;
        if (lastDevice && devices.some(d => d.deviceId === lastDevice)) {
          cameraChoice.value = lastDevice;
        }
      } catch (_) {
        cameraChoice.hidden = true;
      }
    };

    const start = async () => {
      if (scanning) return;
      if (!window.isSecureContext) {
        announce(messages.help);
        return;
      }
      if (!navigator.mediaDevices?.getUserMedia) {
        announce(messages.unsupported);
        return;
      }
      if (typeof window.jsQR !== "function" || !context) {
        announce(messages.library);
        return;
      }

      startButton.disabled = true;
      announce(messages.request);
      try {
        const selected = cameraChoice.value || lastDevice;
        const videoOptions = selected
          ? { deviceId: { ideal: selected } }
          : { facingMode: { ideal: "environment" } };
        stream = await navigator.mediaDevices.getUserMedia({
          video: videoOptions, audio: false
        });
        video.srcObject = stream;
        await video.play();
        scanning = true;
        video.hidden = false;
        startButton.hidden = true;
        stopButton.hidden = false;
        announce(messages.ready);
        await listCameras();
        timeoutId = window.setTimeout(tick, 160);
      } catch (error) {
        stop();
        announce(error?.name === "NotAllowedError" || error?.name === "SecurityError"
          ? messages.denied
          : error?.name === "NotFoundError" ? messages.noCamera
          : error?.name === "NotReadableError" ? messages.busy
          : messages.error);
      } finally {
        startButton.disabled = false;
      }
    };

    startButton.addEventListener("click", start);
    stopButton.addEventListener("click", () => {
      stop();
      announce("");
    });

    cameraChoice.addEventListener("change", async () => {
      lastDevice = cameraChoice.value;
      if (scanning) {
        stop();
        await start();
      }
    });

    photoButton.addEventListener("change", () => {
      const file = photoButton.files?.[0];
      if (!file) return;
      if (typeof window.jsQR !== "function" || !context) {
        announce(messages.library);
        photoButton.value = "";
        return;
      }
      stop();
      const url = URL.createObjectURL(file);
      const image = new Image();
      image.onload = () => {
        try {
          const result = drawFrame(image, image.naturalWidth, image.naturalHeight);
          if (result?.data) foundQr(result.data);
          else announce(messages.imageMissing);
        } catch (_) {
          announce(messages.imageError);
        } finally {
          URL.revokeObjectURL(url);
          photoButton.value = "";
        }
      };
      image.onerror = () => {
        announce(messages.imageError);
        URL.revokeObjectURL(url);
        photoButton.value = "";
      };
      image.src = url;
    });

    window.addEventListener("pagehide", stop);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stop();
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
