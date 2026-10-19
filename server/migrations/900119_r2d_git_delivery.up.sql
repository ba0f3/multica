CREATE TABLE r2d_git_operation (
 id text NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
 spec jsonb NOT NULL,
 outcome text NOT NULL DEFAULT 'pending' CHECK (outcome IN ('pending','succeeded','denied','indeterminate')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE r2d_git_output (
 id uuid NOT NULL, context_id uuid NOT NULL, classification jsonb NOT NULL,
 kind text NOT NULL CHECK (kind IN ('transcript','tool','diff','artifact')),
 body bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 1048576),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION r2d_git_delivery_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='r2d_git_output' THEN
  RAISE EXCEPTION 'immutable Git delivery metadata';
 END IF;
 IF (NEW.id,NEW.spec) IS DISTINCT FROM (OLD.id,OLD.spec) THEN
  RAISE EXCEPTION 'immutable Git delivery metadata';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER r2d_git_operation_immutable BEFORE UPDATE ON r2d_git_operation FOR EACH ROW EXECUTE FUNCTION r2d_git_delivery_immutable();
CREATE TRIGGER r2d_git_output_immutable BEFORE UPDATE ON r2d_git_output FOR EACH ROW EXECUTE FUNCTION r2d_git_delivery_immutable();
