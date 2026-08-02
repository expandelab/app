// =========================================================
// EXPANDELAB / GOLD BIRD — AUTH HELPERS (Supabase Auth)
// =========================================================
// No reinventa login/registro/OAuth: usa el SDK oficial de
// Supabase, que ya maneja hashing de contraseñas, tokens JWT,
// magic links de recuperación y el handshake OAuth con Google.
//
// Requiere:
//   npm install @supabase/supabase-js
//
// Configuración previa en el Dashboard de Supabase:
//   1. Authentication > URL Configuration
//      - Site URL: https://www.expandebot.com (o tu dominio)
//      - Redirect URLs: agregar https://www.expandebot.com/reset-password
//        y https://www.expandebot.com/auth/callback
//   2. Authentication > Providers > Google
//      - Activar, y pegar Client ID / Client Secret de Google Cloud Console
//      - En Google Cloud Console, agregar como Authorized redirect URI:
//        https://<tu-proyecto>.supabase.co/auth/v1/callback
// =========================================================

import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://cezufdzruttkoguokycm.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_cWinuWcDVHhLowQbZSOrXA_18H6icGW';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ---------------------------------------------------------
// 1. REGISTRO (email + contraseña)
// ---------------------------------------------------------
// Al confirmar el email, el trigger handle_new_user() en Postgres
// crea automáticamente la fila correspondiente en public.profiles.
export async function registerWithEmail({ name, email, password }) {
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: { full_name: name }, // queda disponible como raw_user_meta_data en el trigger
      emailRedirectTo: `${window.location.origin}/auth/callback`,
    },
  });
  if (error) throw error;
  return data; // data.user, data.session (session es null si requiere confirmar email)
}

// ---------------------------------------------------------
// 2. LOGIN (email + contraseña)
// ---------------------------------------------------------
export async function loginWithEmail({ email, password }) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;
  return data; // data.session, data.user
}

// ---------------------------------------------------------
// 3. FORGOT PASSWORD — solicitar email de recuperación
// ---------------------------------------------------------
export async function requestPasswordReset(email) {
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${window.location.origin}/reset-password`,
  });
  if (error) throw error;
  return true;
}

// ---------------------------------------------------------
// 3b. RESET PASSWORD — se ejecuta en la página /reset-password
//     después de que el usuario abre el link del correo
//     (Supabase ya autentica la sesión temporal vía el token del link)
// ---------------------------------------------------------
export async function updatePassword(newPassword) {
  const { data, error } = await supabase.auth.updateUser({ password: newPassword });
  if (error) throw error;
  return data;
}

// ---------------------------------------------------------
// 4. LOGIN CON GOOGLE (OAuth)
// ---------------------------------------------------------
export async function loginWithGoogle() {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: `${window.location.origin}/auth/callback`,
      queryParams: { access_type: 'offline', prompt: 'consent' },
    },
  });
  if (error) throw error;
  return data; // redirige automáticamente al flujo de Google
}

// ---------------------------------------------------------
// 5. LOGOUT
// ---------------------------------------------------------
export async function logout() {
  const { error } = await supabase.auth.signOut();
  if (error) throw error;
}

// ---------------------------------------------------------
// 6. OBTENER SESIÓN / PERFIL ACTUAL
// ---------------------------------------------------------
export async function getCurrentProfile() {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;
  const { data: profile, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', user.id)
    .single();
  if (error) throw error;
  return profile;
}

// ---------------------------------------------------------
// 7. LISTENER de cambios de sesión (útil para el header /
//    guardas de ruta en admin.html, merchant.html, etc.)
// ---------------------------------------------------------
export function onAuthStateChange(callback) {
  return supabase.auth.onAuthStateChange((event, session) => {
    callback(event, session); // event: 'SIGNED_IN' | 'SIGNED_OUT' | 'PASSWORD_RECOVERY' | ...
  });
}
