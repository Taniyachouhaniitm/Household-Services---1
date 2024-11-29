from flask import Flask, render_template, session, flash, redirect, url_for, request, jsonify
from matplotlib import pyplot as plt
from project.database import db
from project.config import Config
from project.model import User, Role 
from flask_restful import Api, Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from project.model import db, User 
from functools import wraps
from project.model import ServiceRequest # Ensure this import points to the right location
from flask_login import current_user,LoginManager,login_required,UserMixin, login_user, logout_user,login_manager
from datetime import datetime
from sqlalchemy.orm import joinedload
import base64
import io

hashed_password = generate_password_hash("admin")
print(hashed_password)  



def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config.from_object(Config)

    api = Api(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()

        for role_name in ['admin', 'customer', 'service_professional', 'blocked']:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                db.session.add(Role(name=role_name))

        
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_role = Role.query.filter_by(name='admin').first()
            service_professional_role = Role.query.filter_by(name='service_professional').first()
            admin = User(
                username='admin',
                email='admin@abc.com',
                password=generate_password_hash('admin'),
                roles=[admin_role, service_professional_role]
            )
            db.session.add(admin)
        db.session.commit()

    return app, api


app, api = create_app()



# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')
        email = request.form.get('email')
        fname = request.form.get('fname')  
        lname = request.form.get('lname')  
        approved=True
        if password != cpassword:
            flash("Passwords do not match!", 'danger')
            return render_template('register.html')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken!", 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        
        new_user = User(username=username, email=email, password=hashed_password, fname=fname, lname=lname,approved=approved)

        
        customer_role = Role.query.filter_by(name='customer').first()
        if customer_role:
            new_user.roles.append(customer_role)
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please log in.", 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')



@app.route('/register_service_professional', methods=['GET', 'POST'])
def register_service_professional():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')
        email = request.form.get('email')
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        service_type = request.form.get('service_type')
        service_duration = request.form.get('service_duration')
        experience_year = request.form.get('experience_year')
        service_price = request.form.get('service_price')
        service_description = request.form.get('service_description')

        
        if password != cpassword:
            flash("Passwords do not match!", 'danger')
            return render_template('register_service_professional.html')

        if User.query.filter_by(username=username).first():
            flash("Username already taken!", 'danger')
            return render_template('register_service_professional.html')
        
        if User.query.filter_by(email=email).first():
            flash("Email already taken!", 'danger')
            return render_template('register_service_professional.html')

        hashed_password = generate_password_hash(password)

        service_professional_role = Role.query.filter_by(name='service_professional').first()
        if not service_professional_role:
            flash("Role 'service_professional' not found. Please contact admin.", 'danger')
            return render_template('register_service_professional.html')

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            fname=fname,
            lname=lname,
            approved=False,  
            roles=[service_professional_role]  
        )
        db.session.add(new_user)
        db.session.commit() 

        
        service_professional = ServiceProfessional(
            user_id=new_user.id,
            service_type=service_type,
            service_duration=service_duration,
            experience_year=experience_year,
            service_price=service_price,
            service_description=service_description
        )
        db.session.add(service_professional)
        db.session.commit()

        flash("Registration successful! Please log in.", 'success')
        return redirect(url_for('login'))

    return render_template('register_service_professional.html')


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Modify your login route to use Flask-Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            user_roles = [role.name for role in user.roles]

            if 'blocked' in user_roles:
                flash('Your account has been blocked. Please contact admin.', 'danger')
                return redirect(url_for('login'))

            if 'service_professional' in user_roles and not user.approved:
                flash("Your sign-up request is not approved! Please contact the admin.", 'danger')
                return redirect(url_for('login'))

            if check_password_hash(user.password, password):
                login_user(user)  
                session['user_id'] = user.id  
                session['username'] = user.email  
                session['role'] = user_roles[0]  
                flash("Login successful!", 'success')
                return redirect(url_for('home'))
            else:
                flash("Invalid username or password.", 'danger')
        else:
            flash("User not found.", 'danger')

    return render_template('login.html')



@app.route('/logout')
def logout():
    logout_user()  # Log out the user using Flask-Login
    session.clear()  # Clears all session data, including user_id, username, role, etc.
    flash("You have been logged out successfully.", 'info')
    return redirect(url_for('home'))

#Dummy Admin
admin_email = "admin@abc.com"
admin_password = generate_password_hash("admin")  
username = "admin"
fname = "firstname"
lname = "lname"

admins = {
    admin_email: {
        "password": admin_password,
        "role": "admin",
        "username": username,
        "fname": fname,
        "lname": lname
    }
}


# Admin Login Route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = admins.get(email)
        if user and check_password_hash(user['password'], password):  
            session['user_id'] = email
            session['role'] = user['role']
            session['username'] = email.split('@')[0]  
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')


# Admin Dashboard Route
@app.route('/admin_dashboard')
def admin_dashboard():
    # Data for Users
    total_users = User.query.count()
    approved_users = User.query.filter_by(approved=True).count()
    pending_users = User.query.filter_by(approved=False).count()

    # Data for ServiceRequests
    total_requests = ServiceRequest.query.count()
    accepted_requests = ServiceRequest.query.filter(ServiceRequest.date_of_accept != None).count()
    declined_requests = ServiceRequest.query.filter(ServiceRequest.date_of_accept == None).count()

    # Creating the plots
    user_data = [total_users, approved_users, pending_users]
    request_data = [total_requests, accepted_requests, declined_requests]

    # Plot User Data
    fig_user, ax_user = plt.subplots()
    ax_user.bar(['Total Users', 'Approved Users', 'Pending Users'], user_data, color=['#4caf50', '#2196f3', '#ff9800'])
    ax_user.set_ylabel('Number of Users')
    ax_user.set_title('User Data')

    # Save the plot to a PNG image in memory and encode it in base64
    img_user = io.BytesIO()
    fig_user.savefig(img_user, format='png')
    img_user.seek(0)
    user_img = base64.b64encode(img_user.getvalue()).decode('utf-8')

    # Plot ServiceRequest Data
    fig_request, ax_request = plt.subplots()
    ax_request.bar(['Total Requests', 'Accepted Requests', 'Declined Requests'], request_data, color=['#4caf50', '#2196f3', '#ff9800'])
    ax_request.set_ylabel('Number of Requests')
    ax_request.set_title('Service Request Data')

    # Save the plot to a PNG image in memory and encode it in base64
    img_request = io.BytesIO()
    fig_request.savefig(img_request, format='png')
    img_request.seek(0)
    request_img = base64.b64encode(img_request.getvalue()).decode('utf-8')

    return render_template('admin_dashboard.html', 
                           user_img=user_img, 
                           request_img=request_img)

@app.route('/all_user_details')
def all_user_details():
    try:
        blocked_role = Role.query.filter_by(name='blocked').first()
        users = []
        if blocked_role:
            users = User.query.filter(~User.roles.any(id=blocked_role.id)).all()
        else:
            print("Blocked role not found. Fetching all users.")
            users = User.query.all()
        
        service_professionals = ServiceProfessional.query.all() or []
        return render_template(
            'all_user_details.html', 
            users=users, 
            service_professionals=service_professionals
        )
    except Exception as e:
        import traceback
        print(f"Error: {e}")
        print(traceback.format_exc())
        return "An error occurred while fetching user details."
    
login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/admin/approve/<email>', methods=['GET'])
def approve_service_professional(email):
    user = User.query.filter_by(email=email).first()

    if not user:
        flash(f'User with email {email} not found.', 'danger')
        return redirect(url_for('all_user_details'))

    # Check if the user is a service professional
    if 'service_professional' not in [role.name for role in user.roles]:
        flash(f'User {email} is not a service professional.', 'danger')
        return redirect(url_for('all_user_details'))
    if user.approved:
        flash(f'{email} is already approved as a service professional.', 'info')
        return redirect(url_for('all_user_details'))  
    user.role = 'approved_service_professional'
    user.approved = True

    db.session.commit()
    flash(f'{email} has been approved as a service professional.', 'success')
    
    return redirect(url_for('all_user_details'))

    


@app.route('/admin/block/<email>')
def block_user(email):
    user = User.query.filter_by(email=email).first()

    if user:
        blocked_role = Role.query.filter_by(name='blocked').first()

        if not blocked_role:
            blocked_role = Role(name='blocked')
            db.session.add(blocked_role)
            db.session.commit()

        if blocked_role not in user.roles:
            user.roles.append(blocked_role)  
            db.session.commit()
        return redirect('/all_user_details')  
    else:
        return "User not found", 404


    

@app.route('/view_services', methods=['GET'])
def view_services():
    services = ServiceProfessional.query.all()
    return render_template('view_services.html', services=services)


def get_user_by_email(email):
    return User.query.filter_by(email=email).first()


def get_service_by_id(service_id):
    return ServiceProfessional.query.get(service_id)



@app.route('/admin/service/update/<int:service_id>', methods=['GET', 'POST'])
def update_service(service_id):
    service = ServiceProfessional.query.get(service_id) 
    if not service:
        flash('Service not found.', 'danger')
        return redirect(url_for('view_services'))
    if request.method == 'POST':
        try:
            service.service_type = request.form['service_type']
            service.service_price = float(request.form['service_price'])
            service.service_duration = int(request.form['service_duration'])
            service.service_description = request.form['service_description']

            db.session.commit()
            flash('Service updated successfully!', 'success')
            return redirect(url_for('view_services'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating service: {e}', 'danger')

    return render_template('update_service.html', service_id=service_id, service_professional=service)



# Admin delete service route
@app.route('/admin/service/delete/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    service = get_service_by_id(service_id)  
    if service:
        try:
            db.session.delete(service)
            db.session.commit()
            flash('Service deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting service: {e}', 'danger')
    else:
        flash('Service not found.', 'danger')
    return redirect(url_for('admin_dashboard'))




@app.route('/admin/add_service', methods=['GET', 'POST'])
def add_service():
    if request.method == 'POST':
        service_type = request.form.get('service_type')
        service_duration = request.form.get('service_duration')
        experience_year = request.form.get('experience_year')
        service_description = request.form.get('service_description')
        service_price = request.form.get('service_price')

        app.logger.debug(f"Data to be added: service_type={service_type}, "
                        f"service_duration={service_duration}, "
                        f"experience_year={experience_year}, "
                        f"service_description={service_description}, "
                        f"service_price={service_price}")
        
        if not (service_type and service_duration and experience_year and service_description and service_price):
            flash("All fields (service_type, service_duration, experience_year, service_description, service_price) are required.", 'danger')
            return redirect(url_for('add_service'))

        try:
            service_duration = int(service_duration)
            experience_year = int(experience_year)
            service_price = float(service_price)

        except ValueError:
            flash("Invalid input. Ensure numeric fields are correctly filled.", 'danger')
            return redirect(url_for('add_service'))

        new_service = ServiceProfessional(
            service_type=service_type,
            service_duration=service_duration,
            experience_year=experience_year,
            service_description=service_description,
            service_price=service_price,
            user_id=4
        )
    
        db.session.add(new_service)
        db.session.commit()
        flash(f"Service '{service_type}' added successfully!", 'success')
        return redirect(url_for('view_services'))
        
    return render_template('add_service.html')





@app.route('/create_service_request', methods=['GET', 'POST'])
@login_required
def create_service_request():
    if request.method == 'POST':
        service_professional_id = request.form.get('service_professional_id')
        date_of_request = request.form.get('date_of_request')  

        if not service_professional_id or not date_of_request:
            flash("Please select a service professional and provide a valid date.", 'danger')
            return redirect(url_for('create_service_request'))
        
        try:
            date_of_request = datetime.strptime(date_of_request, "%Y-%m-%d").date()
            
            
            service_professional = ServiceProfessional.query.get(service_professional_id)
            if not service_professional:
                flash("Invalid service professional selected.", 'danger')
                return redirect(url_for('create_service_request'))

            service_type = service_professional.service_type  
            
            date_of_accept = None  

            new_request = ServiceRequest(
                user_id=current_user.id,
                service_professional_id=service_professional_id,
                service_type=service_type,  
                date_of_request=date_of_request,
                date_of_accept=date_of_accept,  
                date_of_completion=None  
            )

            db.session.add(new_request)
            db.session.commit()
            flash("Service request created successfully!", 'success')
            return redirect(url_for('home'))  
        except Exception as e:
            flash(f"Error creating service request: {str(e)}", 'danger')
            db.session.rollback()

    services = ServiceProfessional.query.all()
    return render_template('create_service_request.html', services=services)




@app.route('/view_service_requests', methods=['GET'])
@login_required
def view_service_requests():
    

    requests = ServiceRequest.query.filter(
            ServiceRequest.service_professional_id == ServiceProfessional.id,
            ServiceProfessional.user_id == current_user.id
        ).all()


    print(f"Found {len(requests)} service requests for current service professional: {current_user.id}")
    for req in requests:
        print(f"Request ID: {req.id}, Service Type: {req.service_type}, Customer: {req.user.fname} {req.user.lname}")

    return render_template('view_service_requests.html', requests=requests)


        
@app.route('/accept_service_request/<int:id>', methods=['POST'])
@login_required
def accept_service_request(id):
    service_request = ServiceRequest.query.get_or_404(id)
    
    service_professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()


    if service_request.service_professional_id != service_professional.id:
        flash("You are not authorized to accept this request.", 'danger')
        return redirect(url_for('view_service_requests'))
    
    try:
       
        service_request.date_of_accept = datetime.utcnow()
        db.session.commit()
        flash("Service request accepted successfully.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error accepting service request: {str(e)}", 'danger')
    
    return redirect(url_for('view_service_requests'))




@app.route('/complete_service_request/<int:id>', methods=['POST'])
@login_required
def complete_service_request(id):
    
    service_request = ServiceRequest.query.get_or_404(id)
    
    service_professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()
    
    
    if service_request.service_professional_id != service_professional.id:
        flash("You are not authorized to complete this request.", 'danger')
        return redirect(url_for('view_service_requests'))
    
    try:
        service_request.date_of_completion = datetime.utcnow()
        db.session.commit()
        flash("Service request marked as completed.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error completing service request: {str(e)}", 'danger')
    
    return redirect(url_for('view_service_requests'))


@app.route('/decline_service_request/<int:id>', methods=['POST'])
@login_required
def decline_service_request(id):
    service_request = ServiceRequest.query.get_or_404(id)
    
    service_professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()

   
    if service_request.service_professional_id != service_professional.id:
        flash("You are not authorized to decline this request.", 'danger')
        return redirect(url_for('view_service_requests'))
    
    try:
        service_request.status = 'Declined'
        db.session.commit()
        
        flash("Service request declined successfully.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error declining service request: {str(e)}", 'danger')
    
    return redirect(url_for('view_service_requests'))


@app.route('/user_profile')
@login_required  
def user_profile():
    user = current_user  
    roles = [role.name for role in user.roles] 

    rated_services = []
    if 'customer' in roles:
        rated_services = ServiceRequest.query.filter_by(user_id=current_user.id).filter(ServiceRequest.date_of_completion != None).all()
     
    service_professional = None
    if 'service_professional' in roles:
        service_professional = ServiceProfessional.query.filter_by(user_id=user.id).first()
    
    assigned_requests = []
    if 'service_professional' in roles:
        assigned_requests = ServiceRequest.query.filter(
            ServiceRequest.service_professional_id == user.id
        ).all()
    
    return render_template(
        'user_profile.html',
        user=user,
        roles=roles,
        assigned_requests=assigned_requests,
        rated_services=rated_services,
        service_professional=service_professional
        
    )



@app.route('/search_services', methods=['POST'])
def search_services():
    query = request.form.get('query', '').strip()
    service_professionals = []

    if query:
        service_professionals = (
            ServiceProfessional.query.join(User)  
            .filter(
                db.or_(
                    
                    ServiceProfessional.service_type.ilike(f"%{query}%") 
                )
            ).all()
        )

    return render_template(
        'search_results.html',
        service_professionals=service_professionals,
        query=query
    )


from datetime import date  

@app.route('/rate_service', methods=['GET', 'POST'])
@login_required
def rate_service():
   
    service_request = ServiceRequest.query.filter_by(user_id=current_user.id).order_by(ServiceRequest.date_of_request.desc()).first()
    
    if not service_request:
        flash('No service request found for your account.', 'danger')
        return redirect(url_for('home'))

    
    service_professional = ServiceProfessional.query.get(service_request.service_professional_id)
    
    if not service_professional:
        flash('Service professional not found.', 'danger')
        return redirect(url_for('home'))

   
    if service_request.date_of_completion and service_professional.rating is not None:
        flash('You have already rated this service.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        try:
            
            rating = int(request.form.get('rating', 0))

           
            if rating < 1 or rating > 5:
                flash('Rating must be between 1 and 5 stars.', 'danger')
                return redirect(url_for('rate_service'))

            
            if service_professional.rating:
                service_professional.rating = (service_professional.rating + rating) / 2
            else:
                service_professional.rating = rating

           
            service_request.date_of_completion = date.today()  
            db.session.commit()
            flash('Your rating has been submitted!', 'success')
            return redirect(url_for('home'))

        except ValueError:
            flash('Invalid rating. Please enter a number between 1 and 5.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')


    return render_template(
        'rate_service.html',
        service_request=service_request,
        service_professional=service_professional
    )




@app.route('/')
def home():
    return render_template('index.html')


# API 
class ServiceRequestAPI(Resource):
    def get(self):
        # Fetch all service requests from the database
        service_requests = ServiceRequest.query.all()

        # Convert data into a JSON-friendly format
        response = [
            {
                'id': request.id,
                'user_id': request.user_id,
                'service_type': request.service_type,
                'date_of_request': request.date_of_request.strftime('%Y-%m-%d'),
                'date_of_accept': request.date_of_accept.strftime('%Y-%m-%d') if request.date_of_accept else None,
                'date_of_completion': request.date_of_completion.strftime('%Y-%m-%d') if request.date_of_completion else None,
                'service_professional_id': request.service_professional_id
            }
            for request in service_requests
        ]

        # Return the response as JSON
        return jsonify(response)

# Add the API to your Flask-RESTful application
api.add_resource(ServiceRequestAPI, '/api/service_requests')


from project.model import *

if __name__ == '__main__':
    app.run(debug=True)
