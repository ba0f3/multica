CREATE TABLE IF NOT EXISTS r2d_git_source_quarantine (
 kind text NOT NULL CHECK (kind IN ('workspace','audience','restore')),
 subject_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS r2d_git_restore_checkpoint (
 id uuid NOT NULL, checkpoint uuid NOT NULL
);
CREATE TABLE IF NOT EXISTS r2d_git_output_input (
 output_id uuid NOT NULL, input_id uuid NOT NULL
);
