export function render(text) {
  const node = document.createElement("p");
  node.textContent = text;
  return node;
}

const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
