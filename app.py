from flask import Flask, request, render_template, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
from wtforms import TextAreaField
import json
import pdfkit  # Using pdfkit instead of WeasyPrint

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# Directory to store portfolio JSON files and images
PORTFOLIO_DIR = os.path.join(os.getcwd(), 'portfolios')
IMAGE_DIR = os.path.join(app.root_path, 'static/images')

# Ensure the directories exist
if not os.path.exists(PORTFOLIO_DIR):
    os.makedirs(PORTFOLIO_DIR)

if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

# WTForms
class SignupForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
    submit = SubmitField('Signup')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered!')

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PortfolioForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    about = TextAreaField('About Me', validators=[DataRequired()])

    # Education fields
    school = StringField('School Name', validators=[DataRequired()])
    degree = StringField('Degree', validators=[DataRequired()])
    grade = StringField('Grade', validators=[DataRequired()])
    year_completed = StringField('Year Completed', validators=[DataRequired()])

    # Experience fields
    company = StringField('Company Name', validators=[DataRequired()])
    position = StringField('Position', validators=[DataRequired()])
    years_of_experience = StringField('Years of Experience', validators=[DataRequired()])
    responsibilities = TextAreaField('Responsibilities', validators=[DataRequired()])

    # Projects
    projects = TextAreaField('Projects', validators=[DataRequired()])

    # Skills
    skills = TextAreaField('Skills (comma-separated)', validators=[DataRequired()])

    # Profile picture
    profile_pic = FileField('Profile Picture (PNG only)', validators=[FileAllowed(['png'], 'PNG Images only!')])

    submit = SubmitField('Submit')  

# Helper functions for saving and loading JSON and profile images
def save_portfolio(user_id, data):
    filepath = os.path.join(PORTFOLIO_DIR, f'portfolio_{user_id}.json')
    with open(filepath, 'w') as json_file:
        json.dump(data, json_file)

def load_portfolio(user_id):
    filepath = os.path.join(PORTFOLIO_DIR, f'portfolio_{user_id}.json')
    if os.path.exists(filepath):
        with open(filepath, 'r') as json_file:
            return json.load(json_file)
    return None

def save_profile_picture(profile_pic, user_id):
    filename = f"profile_{user_id}.png"
    filepath = os.path.join(IMAGE_DIR, filename)
    profile_pic.save(filepath)
    return filename

# Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            portfolio = load_portfolio(user.id)
            session['portfolio_created'] = portfolio is not None
            flash('Login successful!', 'success')
            return redirect(url_for('mainpage'))
        else:
            flash('Invalid credentials, please try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def mainpage():
    return render_template('mainpage.html')

@app.route('/create-portfolio', methods=['GET', 'POST'])
def create_portfolio():
    form = PortfolioForm()
    if form.validate_on_submit():
        profile_pic_filename = None
        if form.profile_pic.data:
            profile_pic_filename = save_profile_picture(form.profile_pic.data, session['user_id'])

        portfolio_data = {
            'first_name': form.first_name.data,
            'last_name': form.last_name.data,
            'email': form.email.data,
            'about': form.about.data,

            # Education fields
            'school': form.school.data,
            'degree': form.degree.data,
            'grade': form.grade.data,
            'year_completed': form.year_completed.data,

            # Experience fields
            'company': form.company.data,
            'position': form.position.data,
            'years_of_experience': form.years_of_experience.data,
            'responsibilities': form.responsibilities.data,

            # Projects and Skills
            'projects': form.projects.data,
            'skills': form.skills.data,

            # Profile picture
            'profile_pic': profile_pic_filename,
        }

        save_portfolio(session['user_id'], portfolio_data)
        session['portfolio_created'] = True
        flash('Portfolio created successfully!', 'success')
        return redirect(url_for('view_portfolio'))
    return render_template('create_portfolio.html', form=form)



@app.route('/edit-portfolio', methods=['GET', 'POST'])
def edit_portfolio():
    portfolio = load_portfolio(session['user_id'])
    if not portfolio:
        flash('No portfolio found, please create one first.', 'danger')
        return redirect(url_for('create_portfolio'))

    form = PortfolioForm(data=portfolio)

    if form.validate_on_submit():
        # Check if there's a new profile picture to save
        if isinstance(form.profile_pic.data, str) or form.profile_pic.data is None:
            # If the profile picture is already a string or not uploaded, retain the current one
            profile_pic_filename = portfolio.get('profile_pic')
        else:
            # If a new profile picture is uploaded, save it
            profile_pic_filename = save_profile_picture(form.profile_pic.data, session['user_id'])

        # Update the portfolio data
        portfolio_data = {
            'first_name': form.first_name.data,
            'last_name': form.last_name.data,
            'email': form.email.data,
            'about': form.about.data,

            # Education fields
            'school': form.school.data,
            'degree': form.degree.data,
            'grade': form.grade.data,
            'year_completed': form.year_completed.data,

            # Experience fields
            'company': form.company.data,
            'position': form.position.data,
            'years_of_experience': form.years_of_experience.data,
            'responsibilities': form.responsibilities.data,

            # Projects and Skills
            'projects': form.projects.data,
            'skills': form.skills.data,

            # Profile picture
            'profile_pic': profile_pic_filename,
        }

        save_portfolio(session['user_id'], portfolio_data)
        flash('Portfolio updated successfully!', 'success')
        return redirect(url_for('view_portfolio'))

    return render_template('edit_portfolio.html', form=form, portfolio=portfolio)




@app.route('/view-portfolio')
def view_portfolio():
    portfolio = load_portfolio(session['user_id'])
    if not portfolio:
        flash('No portfolio found, please create one first.', 'danger')
        return redirect(url_for('create_portfolio'))
    return render_template('view_portfolio.html', portfolio=portfolio)

@app.route('/download-pdf')
def download_pdf():
    portfolio = load_portfolio(session['user_id'])
    if not portfolio:
        flash('No portfolio found', 'danger')
        return redirect(url_for('create_portfolio'))

    # Render the portfolio HTML content
    rendered = render_template('view_portfolio_pdf.html', portfolio=portfolio)

    # Generate PDF using pdfkit
    pdf = pdfkit.from_string(rendered, False)

    # Create a response to serve the PDF for download
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=portfolio.pdf'

    return response

@app.route('/contact-me', methods=['GET'])
def contact_me():
    return render_template('contact_me.html')

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8080)
