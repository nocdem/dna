# CPUNK Platform Deployment Guide

## Deployment Server Details

- **Server**: cpunk-deploy (75.119.141.51)
- **Web Root**: /var/www/html
- **User**: deployer
- **SSH Key**: ~/.ssh/cpunk_deploy_user

## Deployment Command

Use rsync to deploy files to the production server:

```bash
cd /home/nocdem/projects/cpunk.club
rsync -avz --no-group --exclude-from=<(echo -e "*.txt\n/doc/\n/devel/\n/configs/\n/certs/\n/backup/\n/js/unused/") ./ cpunk-deploy:/var/www/html/
```

### Important Flags:
- `--no-group`: Prevents group ownership errors (deployment user doesn't have permission to change file groups)
- `-a`: Archive mode (preserves permissions, timestamps, etc.)
- `-v`: Verbose output
- `-z`: Compression during transfer

### Excluded Directories/Files:
- `*.txt`: All text files
- `/doc/`: Documentation directory
- `/devel/`: Development files
- `/configs/`: Configuration files
- `/certs/`: Certificate files  
- `/backup/`: Backup directory
- `/js/unused/`: Unused JavaScript files

## Post-Deployment

After deployment, log the deployment:

```bash
echo "$(date '+%Y-%m-%d %H:%M:%S') - Deployed [description of changes]" >> /home/nocdem/projects/deployment.log
```

## Notes

- The rsync errors about "chgrp failed: Operation not permitted" are non-fatal and can be ignored
- Using `--no-group` flag prevents these warnings from appearing
- Files are still copied successfully even with the warnings