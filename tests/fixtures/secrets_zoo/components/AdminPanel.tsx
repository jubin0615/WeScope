"use client";
import { createClient } from "@supabase/supabase-js";

// expect: secret-client-bundle
const supabase = createClient("https://x.supabase.co", "{{FAKE:service_role}}");
// expect: secret-frontend-env
const serviceKey = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

export default function AdminPanel() {
  return null;
}
