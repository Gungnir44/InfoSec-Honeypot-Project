# Windows Quick Start Guide

Get the honeypot dashboard running on Windows in 5 minutes!

## Step 1: Install Dependencies (DONE! ✓)

You just ran:
```bash
pip install -r requirements-local.txt
```

This installs everything needed for local testing with SQLite (no PostgreSQL required).

## Step 2: Set Up Environment

```bash
# Copy the example environment file
copy .env.example .env
```

The defaults work fine for local testing - you don't need to change anything.

## Step 3: Initialize Database

```bash
# Create the SQLite database and tables
python scripts/setup_database.py
```

Press 'y' when prompted.

## Step 4: Add Sample Data

```bash
# Generate 100 fake attacks to visualize
python scripts/add_sample_data.py --count 100
```

This creates realistic sample data so you can see how everything works.

## Step 5: Start the Dashboard

```bash
# Start the web dashboard
python dashboard/app.py
```

You should see:
```
╔══════════════════════════════════════════╗
║   Honeypot Dashboard Server Starting     ║
╚══════════════════════════════════════════╝

Server: http://0.0.0.0:5000
Environment: Development
```

## Step 6: Open Your Browser

Open: **http://localhost:5000**

You should see:
- 📊 Statistics cards with attack counts
- 🗺️ World map showing attack origins
- 📈 Charts with attack patterns
- 🔴 Recent attack feed

## What You're Seeing

All the data is **fake/sample data** right now - perfect for testing! When you deploy the real honeypot to a VPS, you'll see actual attack data instead.

## Next Steps

### To Explore the Code
```bash
# Open in VS Code
code .
```

Key files to check out:
- `backend/ml/feature_engineering.py` - See the 30+ features extracted
- `backend/analyzers/command_analyzer.py` - Command categorization
- `dashboard/templates/dashboard.html` - Dashboard layout
- `backend/database/models.py` - Database structure

### To Test ML Features

Once you have the dashboard running:

```bash
# Open a new terminal
# Train ML models on sample data
python backend/ml/training.py --mode both

# Export dataset for research
python backend/ml/training.py --mode export
```

### To Run Tests

```bash
# Run the test suite
pytest tests/ -v
```

### To Explore Data with Jupyter

```bash
# Install Jupyter (if you want)
pip install jupyter notebook

# Start Jupyter
jupyter notebook

# Open notebooks/01_exploratory_analysis.ipynb
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'X'"
Some packages didn't install. Run:
```bash
pip install -r requirements-local.txt --upgrade
```

### "Database connection failed"
Make sure you ran `python scripts/setup_database.py` first.

### Dashboard won't start
Check the error message. Common issues:
- Port 5000 already in use (close other apps using port 5000)
- Missing `.env` file (copy from `.env.example`)

### No data showing up
Run the sample data script:
```bash
python scripts/add_sample_data.py --count 100
```

## What's Different from Production?

**Local (what you're running now):**
- SQLite database (no PostgreSQL needed)
- Sample/fake attack data
- Development mode (auto-reload on code changes)
- No real honeypot (testing only)

**Production (when deployed to VPS):**
- PostgreSQL database
- Real attack data from Cowrie honeypot
- Production mode (optimized, stable)
- Actual attackers trying to break in!

## Ready for Real Deployment?

Once you've tested locally and understand how it works:

1. Provision a VPS ($6-12/month)
2. Follow **docs/QUICKSTART.md** for deployment
3. Wait 24-48 hours for attacks
4. Train ML models on real data
5. Present your findings to class!

## Getting Help

- Check **GETTING_STARTED.md** for detailed guidance
- Review **docs/SETUP.md** for VPS deployment
- Read **PROJECT_SUMMARY.md** to understand what was built

## You're All Set!

The dashboard should be running now. Open **http://localhost:5000** and explore!

When you're ready to see REAL attacks, follow the deployment guide to put this on a VPS.

Happy hunting! 🍯🎯
