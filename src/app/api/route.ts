import { json } from "@/lib/vril/framework";

export async function GET() {
  return json({ message: "Hello, world!" });
}
