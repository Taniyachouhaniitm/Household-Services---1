from main import app
from flask import render_template, session, url_for, redirect, request ,flash,jsonify
from project.model import *
from werkzeug.security import generate_password_hash ,check_password_hash
from flask_login import current_user,login_required
from datetime import datetime

@app.route('/')
def home():
    return render_template('index.html')

#login for customer and service professional
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            user_roles = [role.name for role in user.roles]

            if 'blocked' in [role.name for role in user.roles]:
                flash('Your account has been blocked. Please contact admin.', 'danger')
                return redirect(url_for('login'))

            if 'service_professional' in user_roles and not user.approved:
                flash("Your sign-up request is not approved! Please contact the admin.", 'danger')
                return redirect(url_for('login'))

            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['roles'] = user_roles
                session['role'] = session['roles'][0]
                flash("Login successful!", 'success')
                return redirect(url_for('home'))
            else:
                flash("Invalid username or password.", 'danger')
        else:
            flash("User not found.", 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash("You have been logged out successfully.", 'info')
    return redirect(url_for('home'))


#resigter for customer
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    if request.method == 'POST':
        print("POST request received")  # Debugging statement
        username = request.form.get('username', None)
        email = request.form.get('email', None)
        password = request.form.get('password', None)
        cpassword = request.form.get('cpassword', None)
        role = request.form.get('role', None)
        fname = request.form.get('fname',None)  
        lname = request.form.get('lname',None) 
        print(f"Username: {username}, Email: {email}, Role: {role},Fname:{fname},Lname:{lname}")  # Debugging

        if not username:
            flash('Username is required')
            return redirect(url_for('register'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('login'))

        if not email:
            flash('Email is required')
            return redirect(url_for('register'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists')
            return redirect(url_for('login'))

        if not password and not cpassword:
            flash('Password is required')
            return redirect(url_for('register'))

        if password != cpassword:
            flash('Password and Confirm Password must be same')
            return redirect(url_for('register'))

        if not role:
            flash('Role is required')
            return redirect(url_for('register'))

        approved = True
        if role == 'customer':
            approved = False

    
        user = User(
        username=username,
        email=email,
        password=password,
        approved=approved,
        roles=[Role.query.filter_by(name="customer").first()]
    )

        db.session.add(user)
        db.session.commit()
        flash('User created successfully')
        return redirect(url_for('login'))
    

#register_service_professional
@app.route('/register_service_professional', methods=['GET', 'POST'])
def register_service_professional():
    if request.method == 'POST':
        username = request.form.get('username', None)
        email = request.form.get('email', None)
        password = request.form.get('password', None)
        cpassword = request.form.get('cpassword', None)
        role = request.form.get('role', None)
        fname = request.form.get('fname', None)
        lname = request.form.get('lname', None)
        service_type = request.form.get('service_type')
        service_duration = request.form.get('service_duration')
        experience_year = request.form.get('experience_year')
        service_description = request.form.get('service_description')
        service_price = request.form.get('service_price')

        print(f"Username: {username}, Email: {email}, Role: {role}, Fname: {fname}, Lname: {lname}, Service_type: {service_type}, Service_duration: {service_duration}, Experience_year: {experience_year}, Service_description: {service_description}, Service_price: {service_price}")

        if not username:
            flash('Username is required', 'error')
            return redirect(url_for('register_service_professional'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register_service_professional'))

        if not email:
            flash('Email is required', 'error')
            return redirect(url_for('register_service_professional'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('register_service_professional'))

        if not password or not cpassword:
            flash('Password is required', 'error')
            return redirect(url_for('register_service_professional'))

        if password != cpassword:
            flash('Password and Confirm Password must match', 'error')
            return redirect(url_for('register_service_professional'))

        if not role or role != 'service_professional':
            flash('Invalid role. Only service professionals can register here.', 'error')
            return redirect(url_for('register_service_professional'))
        
        approved = True
        if role == 'service_professional':
            approved = False

        user = User(
        username=username,
        email=email,
        password=password,
        fname=fname,
        lname=lname,
        approved=approved,
        roles=[Role.query.filter_by(name="service_professional").first()]  # Assign service professional role
)
        db.session.add(user)
        db.session.commit()

        service_professional = ServiceProfessional(
            service_type=service_type,
            service_duration=int(service_duration),
            experience_year=int(experience_year),
            service_description=service_description,
            service_price=float(service_price),
            user_id=user.id  
        )
        db.session.add(service_professional)
        db.session.commit()

        flash("Service Professional registered successfully!", "success")
        return redirect(url_for('login'))

    return render_template('register_service_professional.html')


# From here work on admin page start 

def get_user_by_email(email):
    return next((user for user in User['email']==email),None)


def get_service_by_id(service_id):
    return next((service for service in ServiceProfessional if service['id'] == service_id), None)


#Dummy Admin
admin_email = "admin@abc.com"
admin_password = generate_password_hash("admin")  # Store this hash securely
username = "admin"
fname = "firstname"
lname = "lname"

admins = {
    admin_email: {
        "password": admin_password,  # Hashed password
        "role": "admin",
        "username": username,
        "fname": fname,
        "lname": lname
    }
}


# Login for admin
@app.route('/admin/login',methods=['GET','POST'])
def admin_login():
    if request.method=='POST':
        email=request.form['email']
        password=request.form['password']

        if email==admin_email and check_password_hash(admin_password,password):
            session['email']=email
            session['role']='admin'
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password ','danger')
            return redirect(url_for('admin_login'))
    return redirect(url_for('admin_login'))


# Admin Dashboard in which add service available
@app.route('/admin/dashboard')
def admin_dashboard():
    if current_user.role != 'admin':
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()  
    services = ServiceProfessional.query.all()  
    print(users)  
    print(services) 
    return render_template('admin_dashboard.html', users=users, services=services)


# Admin approve service professional route in all_user_details
@app.route('/admin/approve/<email>', methods=['GET'])
def approve_service_professional(email):
    try:
        
        user = User.query.filter_by(email=email).first()
    
        if user and 'service_professional' in [role.name for role in user.roles]:
            user.role = 'approved_service_professional'
            user.approved = True  
            db.session.commit()  
            flash(f'{email} has been approved as a service professional.', 'success')
        else:
            flash(f'User {email} not found or is not a service professional.', 'danger')
        
        return redirect(url_for('user_approvals'))  
    
    except Exception as e:
        app.logger.error(f"Error approving user {email}: {e}")
        flash("An error occurred while approving the user. Please try again later.", 'danger')
        return redirect(url_for('all_user_details'))




#Admin Block users route in all_user_details
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


# view_services in this page services present which we can edit(update) and delete
@app.route('/view_services', methods=['GET'])
def view_services():
    services = ServiceProfessional.query.all()
    return render_template('view_services.html', services=services)


def get_user_by_email(email):
    return User.query.filter_by(email=email).first()


def get_service_by_id(service_id):
    return ServiceProfessional.query.get(service_id)


#update_service in view_services
@app.route('/update_service', methods=['POST'])
def update_service():
    service_id = request.form['service_id']
    new_data = request.form['new_data']
    service_professional = ServiceProfessional.query.get(service_id)
    if service_professional:
        service_professional.data_field = new_data
        db.session.commit()
        return redirect('/success')  
    return redirect('/failure')


# delete service route in view_services
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




# add_services in admin dashboard
@app.route('/admin/add_service', methods=['GET', 'POST'])
def add_service():
    if request.method == 'POST':
        # Retrieve form data and log it
        service_type = request.form.get('service_type')
        service_duration = request.form.get('service_duration')
        experience_year = request.form.get('experience_year')
        service_description = request.form.get('service_description')
        service_price = request.form.get('service_price')

        app.logger.debug(f"Form Data: service_type={service_type}, "
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
        try:
            db.session.add(new_service)
            db.session.commit()
            flash(f"Service '{service_type}' added successfully!", 'success')
            return redirect(url_for('view_services'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding service: {str(e)}", exc_info=True)
            flash("An error occurred while adding the service.", 'danger')

    return render_template('add_service.html')

# End of Admin page routes




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
            new_request = ServiceRequest(
                user_id=current_user.id,
                service_professional_id=int(service_professional_id),
                date_of_request=datetime.strptime(date_of_request, "%Y-%m-%d").date()
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
    requests = ServiceRequest.query.filter_by(user_id=ServiceProfessional.id).all()
    print(f"Found {len(requests)} service requests for current user: {current_user.id}")
    for req in requests:
        print(f"Request ID: {req.id}, Service Type: {req.service_type}, Customer: {req.user.fname} {req.user.lname}")
    return render_template('view_service_requests.html', requests=requests)


@app.route('/user_profile')
def user_profile():
    user = User.query.get(current_user.id)
    
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))
    
    return render_template('user_profile.html', user=user)



@app.route('/search_services', methods=['POST'])
def search_services():
    query = request.form.get('query', '').strip()
    service_professionals = []

    if query:
        service_professionals = (
            ServiceProfessional.query.join(User)  # Join with User for names
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

@app.route('/rate_service/<int:id>', methods=['GET', 'POST'])
@login_required
def rate_service(id):
    service_request = ServiceRequest.query.get(id)
    
    if not service_request:
        flash("Service request not found.", "danger")
        return redirect(url_for('view_service_requests'))  # Or another redirect path
    
    if service_request.date_of_completion is None:
        flash("You can only rate completed service requests.", "danger")
        return redirect(url_for('view_service_requests'))  # Or another redirect path

    if request.method == 'POST':
        rating = request.form.get('rating')
        if int(rating) < 1 or int(rating) > 5:
            flash("Rating must be between 1 and 5.", "danger")
        else:
            service_request.rating = rating
            try:
                db.session.commit()
                flash("Thank you for your rating!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Error submitting rating: {str(e)}", "danger")
        return redirect(url_for('view_service_requests'))  # Or another redirect path

    return render_template('rate_service.html', service_request=service_request)



# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('admin_login'))


