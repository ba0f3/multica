import { redirect } from "next/navigation";

type Props = {
  params: Promise<{ workspaceSlug: string }>;
};

// MUL-9005 removed the builder start screen; conversations live at
// `.../ai/[sessionId]`. Keep a leaf route so Next.js typed-route validation
// and stray `/agents/new/ai` hits return to step 1.
export default async function NewAgentAiIndexRoute({ params }: Props) {
  const { workspaceSlug } = await params;
  redirect(`/${workspaceSlug}/agents/new`);
}
