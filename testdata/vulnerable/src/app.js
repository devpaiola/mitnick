const html = { dangerouslySetInnerHTML: { __html: userProvidedText } }; // mitnick:ignore WEB001 -- synthetic fixture demonstrates justified suppression
eval(userProvidedText);
const supabaseSecret = process.env.NEXT_PUBLIC_SUPABASE_SECRET_KEY;
