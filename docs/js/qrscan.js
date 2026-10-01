// QR scanning for destination addresses: the camera through getUserMedia, the
// browser's BarcodeDetector when it exists, otherwise jsQR on video frames.
// A payment URI (bitcoin:..., alephium:...) is reduced to its address.
import jsQR from 'jsqr';

export function addressFromQrText(text) {
  let t = String(text || '').trim();
  const m = t.match(/^(?:bitcoin|alephium|alph):(.+)$/i);
  if (m) t = m[1];
  return t.split('?')[0].split('&')[0].trim();
}

export function decodeImageData(imageData) {
  const r = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'attemptBoth' });
  return r ? r.data : null;
}

// Starts the camera in `video`, calls onResult(text) once a code is read, and
// returns a stop() that releases the camera. onError(message) reports failures.
export async function scanWithCamera(video, onResult, onError) {
  let stream, stopped = false, detector = null;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
  } catch (e) { onError(e.name === 'NotAllowedError' ? 'Camera access was refused' : `Camera unavailable: ${e.message}`); return () => {}; }
  video.srcObject = stream; video.setAttribute('playsinline', ''); await video.play().catch(() => {});
  if ('BarcodeDetector' in window) { try { detector = new window.BarcodeDetector({ formats: ['qr_code'] }); } catch { detector = null; } }
  const canvas = document.createElement('canvas'); const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const stop = () => { stopped = true; for (const t of stream.getTracks()) t.stop(); video.srcObject = null; };
  const tick = async () => {
    if (stopped) return;
    try {
      if (video.readyState >= 2) {
        let text = null;
        if (detector) { const codes = await detector.detect(video); text = codes[0]?.rawValue || null; }
        else {
          const w = video.videoWidth, h = video.videoHeight;
          if (w && h) { canvas.width = w; canvas.height = h; ctx.drawImage(video, 0, 0, w, h); text = decodeImageData(ctx.getImageData(0, 0, w, h)); }
        }
        if (text) { stop(); onResult(text); return; }
      }
    } catch (e) { onError(`Scan failed: ${e.message}`); stop(); return; }
    setTimeout(tick, 150);
  };
  tick();
  return stop;
}
