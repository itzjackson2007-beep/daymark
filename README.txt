DAYMARK

Open index.html for normal local use.

For offline caching and install support, double-click run-daymark.bat. It serves Daymark from localhost, which the browser requires for service workers and PWA installation. Use the browser's Install option after Daymark opens.

Tasks are stored only in this browser. Profile > Manage backups downloads encrypted JSON backups. Keep the six-word PIN used when downloading each backup; that PIN is needed to restore it later. Daymark checks the backup integrity and task data before importing or restoring it. Older plain JSON backups are still accepted after task validation.

If you enable local task encryption, your six-word PIN and recovery answers can unlock that browser's task data. Forgetting both means the encrypted data cannot be recovered.

After five incorrect profile PIN attempts, Daymark temporarily blocks further attempts. The wait grows after repeated lockouts.

CSS uses system fonts so the interface does not download fonts from the internet.
