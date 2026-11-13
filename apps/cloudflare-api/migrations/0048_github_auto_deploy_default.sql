-- Automatic production deployment is the default for every newly linked repository.
-- Existing projects are opted in as well; owners can still explicitly disable it
-- from Deploy settings after linking.
UPDATE github_projects SET auto_deploy = 1 WHERE auto_deploy = 0;

CREATE TRIGGER IF NOT EXISTS github_projects_auto_deploy_default
AFTER INSERT ON github_projects
WHEN NEW.auto_deploy = 0
BEGIN
  UPDATE github_projects SET auto_deploy = 1 WHERE id = NEW.id;
END;
