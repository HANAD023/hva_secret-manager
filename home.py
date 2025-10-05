from flask import Blueprint, render_template

# Create blueprint
home = Blueprint('home', __name__)

@home.route('/')
def index():
    return render_template('home/index.html')
