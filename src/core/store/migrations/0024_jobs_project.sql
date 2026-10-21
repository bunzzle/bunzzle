CREATE INDEX jobs_project_ready ON jobs (project_id, priority, run_after) WHERE state = 'ready';
