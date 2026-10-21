const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const crypto = require('node:crypto');

initializeApp();
const db = getFirestore();
const REGION = 'us-central1';
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 20;

function normalizeSecret(value) {
  return typeof value === 'string' ? value.trim().toUpperCase() : '';
}

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

async function checkRateLimit(ip) {
  const ipHash = sha256(String(ip || 'unknown'));
  const ref = db.collection('secretKeyRateLimits').doc(ipHash);
  const now = Date.now();
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const previous = snap.exists && Array.isArray(snap.data().attempts)
      ? snap.data().attempts.filter((stamp) => Number(stamp) > now - RATE_LIMIT_WINDOW_MS)
      : [];
    if (previous.length >= RATE_LIMIT_MAX) {
      throw new HttpsError('resource-exhausted', 'Demasiados intentos. Vuelve a intentarlo más tarde.');
    }
    previous.push(now);
    tx.set(ref, {
      attempts: previous,
      updatedAt: FieldValue.serverTimestamp(),
      expireAt: new Date(now + 24 * 60 * 60 * 1000),
    }, { merge: true });
  });
}

/**
 * Valida una Secret Key aleatoria (192 bits), busca únicamente su hash y devuelve
 * un custom token firmado por Firebase Admin. Nunca acepta un UID del cliente.
 */
exports.redeemSecretKey = onCall({
  region: REGION,
  // Permit browser origins used by GitHub Pages and mobile WebViews.
  // CORS is not authentication: the server still validates the high-entropy key,
  // rate-limits attempts, and signs the Firebase custom token only on success.
  cors: true,
  maxInstances: 10,
}, async (request) => {
  await checkRateLimit(request.rawRequest?.ip || 'unknown');

  const secretKey = normalizeSecret(request.data?.secretKey);
  if (!/^AEV(?:-[0-9A-F]{8}){4}-[0-9A-F]{16}$/.test(secretKey)) {
    throw new HttpsError('unauthenticated', 'La Secret Key no es válida.');
  }

  const secretHash = sha256(secretKey);
  const matches = await db.collection('vendedores')
    .where('secret_key_hash', '==', secretHash)
    .limit(2)
    .get();

  // Mensaje genérico para no revelar si una clave existe, pertenece a una cuenta
  // suspendida o está duplicada.
  if (matches.size !== 1) {
    throw new HttpsError('unauthenticated', 'No se pudo validar la Secret Key.');
  }

  const sellerDoc = matches.docs[0];
  const seller = sellerDoc.data();
  if (seller.cuenta_suspendida === true || seller.estado_cuenta === 'suspendida') {
    throw new HttpsError('permission-denied', 'Esta cuenta está suspendida.');
  }

  const user = await getAuth().getUser(sellerDoc.id);
  if (user.disabled) {
    throw new HttpsError('permission-denied', 'Esta cuenta no está disponible.');
  }

  const customToken = await getAuth().createCustomToken(sellerDoc.id, {
    role: 'vendedor',
    loginMethod: 'secret_key',
  });
  return { customToken };
});

/** Registra una solicitud verificable de eliminación. No borra datos parcialmente. */
exports.requestAccountDeletion = onCall({
  region: REGION,
  cors: true,
  maxInstances: 5,
}, async (request) => {
  if (!request.auth?.uid) {
    throw new HttpsError('unauthenticated', 'Debes iniciar sesión para solicitar la eliminación.');
  }
  if (request.data?.confirmacion !== 'ELIMINAR') {
    throw new HttpsError('invalid-argument', 'La confirmación no es válida.');
  }

  const uid = request.auth.uid;
  const user = await getAuth().getUser(uid);
  const ref = db.collection('solicitudes_eliminacion').doc(uid);
  await ref.set({
    uid,
    email: user.email || '',
    estado: 'pendiente',
    solicitado_en: FieldValue.serverTimestamp(),
    origen: 'panel_vendedor',
  }, { merge: true });
  return { ok: true, status: 'pending' };
});
