-- Default GitHub provider for self-hosted / dev stacks using database custody.
INSERT INTO r2d_git_provider (id, label, kind, host, port, host_pins, enabled)
SELECT
    'a0000000-0000-4000-8000-000000000001'::uuid,
    'GitHub',
    'github',
    'github.com',
    22,
    '["SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s", "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"]'::jsonb,
    true
WHERE NOT EXISTS (
    SELECT 1 FROM r2d_git_provider WHERE kind = 'github' AND host = 'github.com'
);
