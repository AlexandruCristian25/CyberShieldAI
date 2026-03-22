# Deployment Guide

## Backend (Render)
1. Push your backend to GitHub
2. Create new Web Service on [Render](https://render.com)
3. Add secrets: `SECRET_KEY`, `ROTATED_KEY`, `DB_URL`, `S3_ACCESS_KEY`, etc.
4. Enable auto-deploy

## Frontend (Vercel)
1. Push frontend to GitHub
2. Import on [Vercel](https://vercel.com)
3. Configure `.env` in dashboard with `REACT_APP_API_URL`

## Database
Use PostgreSQL managed by Render or Railway

## Backup
Set up S3 bucket and use `/backup/cron_backup.py` to schedule automatic daily uploads.