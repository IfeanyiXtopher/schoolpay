import json, random, string, os

from datetime import date

from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask import render_template, request, abort, redirect, flash, redirect, session, url_for, jsonify

# local imports
from project_package import myapp, mail, Message, csrf
from project_package.models import *
from project_package.myforms import *

import secrets

current_date = date.today()

def login_required(f):
    @wraps(f)#this ensures that details(meta data) about the original function f, that is being decorated is still available ### we wont be needing to check if session.get('userloggedin') == None or session.get('role') != "admin"
    def login_check(*args,**kwargs):
        if session.get("adminuser") != None:
            return f(*args,**kwargs)
        else:
            flash("Access denied")
            return redirect('/admin/login')
    return login_check 
#To use login_required, place it after the route decorator over any route that needs authentication

@myapp.route("/admin/login/", methods=["POST","GET"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_folder/admin_login.html")
    else:
        logdeet = request.form.get("username")
        pwd = request.form.get("pwd")
        verify = db.session.query(Admin).filter((Admin.admin_email == logdeet) | (Admin.admin_staffid == logdeet)).first()

        if verify and check_password_hash(verify.admin_password, pwd):
            session["adminuser"] = verify.admin_id
            session["role"] = "admin"
            
            if verify.is_default_pwd:
                flash("Please change your default password.", category="error")
                return redirect(url_for('change_password')) # Replace 'change_password_route' with the route name for the change password page
            else:
                return redirect(url_for('admin_dash'))
        else:
            flash("Invalid Login credentials", category="error")
            return redirect(url_for("admin_login"))


        
@myapp.route("/admin/")
def admin_page():
    if session.get("adminuser") == None or session.get("role") != "admin":
        flash("Please login")
        return render_template("admin_folder/admin_login.html")
    else:
        return render_template("admin_folder/dashboard.html")


@myapp.context_processor
def inject_admin_deets():
    admin_id = session.get("adminuser")
    if admin_id:
        admin = Admin.query.get(admin_id)
        if admin:
            return {'current_admin':admin}
    return {}


@myapp.route("/admin/dashboard/")
def admin_dash():
    if session.get("adminuser") == None or session.get("role") != "admin":
        return render_template("admin_folder/admin_login.html")
    else:
        stddeets = db.session.query(Students).all()
        parentsdeets = db.session.query(Parents).all()
        staffdeets = db.session.query(Admin).all()
        awaitingpayments = Payments.query.filter_by(pay_status="Awaiting Confirmation").all()
        confirmed = Payments.query.filter_by(pay_status="Confirmed").all()
        payments = Payments.query.limit(4).all()
        overdue_payments = StudentFees.query.join(Fees).filter(Fees.fees_duedate < current_date, StudentFees.stdfee_status != 'Paid').all()
        return render_template("admin_folder/dashboard.html",payments=payments, stddeets=stddeets, parentsdeets=parentsdeets, overdue_payments=overdue_payments, confirmed=confirmed, staffdeets=staffdeets, awaitingpayments=awaitingpayments)
    
@myapp.route("/admin/logout")
def admin_logout():
    if session.get("adminuser") != None:
        session.pop("adminuser",None)
        session.pop("role",None)
        flash("Your are logged out", category="INFO")
        return redirect(url_for("admin_login"))
    else:
        return redirect(url_for('admin_login'))


@myapp.route("/admin/addfee/", methods=["POST", "GET"])
def add_fee():
    if request.method == "GET":
        sessions = db.session.query(Academic_session).all()
        levels = db.session.query(Studentlevel).all()
        terms = db.session.query(Academic_term).all()
        classes = db.session.query(Studentclass).all()
        return render_template('admin_folder/addfee.html', sessions=sessions, levels=levels, terms=terms, classes=classes)
    else:
        feedesc = request.form.get('feedesc')
        amount = float(request.form.get('feeAmount'))
        acases_year = request.form.get('acaSession')
        acaterm_name = request.form.get('feeterm')
        level_name = request.form.get('acalevel')
        acaclass_name = request.form.get('acaClass')
        duedate = request.form.get('duedate')

        # Fetch or create Studentlevel
        level = Studentlevel.query.filter_by(level_name=level_name).first()
        if not level:
            level = Studentlevel(level_name=level_name)
            db.session.add(level)
            db.session.commit()

        # Fetch or create Studentclass
        acaclass = Studentclass.query.filter_by(class_name=acaclass_name.upper().replace(" ", "")).first()
        if not acaclass:
            acaclass = Studentclass(class_name=acaclass_name.upper().replace(" ", ""))
            db.session.add(acaclass)
            db.session.commit()

        # Fetch or create Academic_session
        acases = Academic_session.query.filter_by(acases_year=acases_year).first()
        if not acases:
            acases = Academic_session(acases_year=acases_year)
            db.session.add(acases)
            db.session.commit()

        # Fetch or create Academic_term
        acaterm = Academic_term.query.filter_by(acaterm_name=acaterm_name).first()
        if not acaterm:
            acaterm = Academic_term(acaterm_name=acaterm_name)
            db.session.add(acaterm)
            db.session.commit()

        fee = Fees(fees_levelid=level.level_id, fees_classid=acaclass.class_id, fees_desc=feedesc,
                   fees_amount=amount, fees_acatermid=acaterm.acaterm_id, fees_acasesid=acases.acases_id, fees_duedate=duedate)
        db.session.add(fee)
        db.session.commit()

         # Get all students with matching class and level
        matching_students = Students.query.filter_by(std_studentclassid=fee.fees_classid, std_studentlevelid=fee.fees_levelid).all()

        for student in matching_students:
        # Check if a StudentFees record already exists for this student and fee
            existing_std_fee = StudentFees.query.filter_by(stdfee_std_id=student.std_id, stdfee_fee_id=fee.fees_id).first()
        
            if not existing_std_fee:
                new_std_fee = StudentFees(
                    stdfee_amount=fee.fees_amount,
                    stdfee_std_id=student.std_id,
                    stdfee_fee_id=fee.fees_id
                )
                db.session.add(new_std_fee)
                db.session.commit()

        flash("Fee Added Successfully")
        return redirect('/admin/addfee/')
    

@myapp.route("/admin/editfee/<fee_id>/", methods=["POST", "GET"])
def edit_fee(fee_id):
    fee = Fees.query.get(fee_id)
    if not fee:
        flash('Fee not found', 'error')
        return redirect('/admin/dashboard/')

    if request.method == "GET":
        sessions = db.session.query(Academic_session).all()
        levels = db.session.query(Studentlevel).all()
        terms = db.session.query(Academic_term).all()
        classes = db.session.query(Studentclass).all()
        return render_template('admin_folder/edit_fee.html', deets=fee, sessions=sessions, levels=levels, terms=terms, classes=classes)
    
    else:
    # Get values from form
        new_fee_desc = request.form.get('feedesc')
        new_fee_amount = float(request.form.get('feeAmount'))
        new_acases_id = request.form.get('acaSession')
        new_acaterm_id = request.form.get('feeterm')
        new_level_id = int(request.form.get('acalevel'))
        new_class_id = int(request.form.get('acaClass'))
        new_due_date = request.form.get('duedate')

    # If there's a change in the fee amount, update the associated StudentFees records:
    if fee.fees_amount != new_fee_amount:
        matching_students_fees = StudentFees.query.filter_by(stdfee_fee_id=fee.fees_id).all()
        for student_fee in matching_students_fees:
            student_fee.stdfee_amount = new_fee_amount

    # Check if level or class has changed
    if fee.fees_levelid != new_level_id or fee.fees_classid != new_class_id:
        try:
            # Delete all current associations of this fee with students
            StudentFees.query.filter_by(stdfee_fee_id=fee.fees_id).delete()
            db.session.commit()
            flash('Old associations deleted successfully!')

            # Fetch all students matching the new class and level
            matching_students = Students.query.filter_by(std_studentclassid=new_class_id, std_studentlevelid=new_level_id).all()

            for student in matching_students:
                new_std_fee = StudentFees(
                    stdfee_amount=new_fee_amount,
                    stdfee_std_id=student.std_id,
                    stdfee_fee_id=fee.fees_id
                )
                db.session.add(new_std_fee)

            fee.fees_levelid = new_level_id
            fee.fees_classid = new_class_id

        except Exception as e:
            flash(f'Error while deleting old associations: {e}')

    # Finally, update the main fee record
    fee.fees_desc = new_fee_desc
    fee.fees_amount = new_fee_amount
    fee.fees_acasesid = new_acases_id
    fee.fees_acatermid = new_acaterm_id
    fee.fees_duedate = new_due_date

    db.session.commit()
    flash('Fee and associated student fees updated successfully', 'success')
    return redirect('/admin/dashboard/')


@myapp.route("/admin/deletefee/<int:fee_id>/", methods=["GET"])
def delete_fee(fee_id):
    fee = Fees.query.get_or_404(fee_id)
    
    # Also delete related StudentFees records
    StudentFees.query.filter_by(stdfee_fee_id=fee.fees_id).delete()
    
    db.session.delete(fee)
    db.session.commit()

    flash("Fee and its associated student fees have been deleted!", "success")
    return redirect(url_for('fees_records'))


@myapp.route("/admin/admin_records/")
def admin_records():
    admins = db.session.query(Admin).all()
    return render_template("admin_folder/admin_records.html", admins=admins)

@myapp.route("/admin/awaiting_confirmation/")
def add_awaitingconf():
    payments = Payments.query.filter_by(pay_status="Awaiting Confirmation").all()
    return render_template('admin_folder/awaiting_payment_confirmation.html', payments=payments)


@myapp.route("/admin/changedp/", methods=["GET","POST"])
def changedp():
    id = session.get('adminuser')
    userdeets = db.session.query(Admin).get(id)
    dpform = DpForm()
    if request.method == 'GET':
        return render_template("admin_folder/changedp.html",dpform=dpform, userdeets=userdeets)
    else:#form is being submitted
        if dpform.validate_on_submit():
            pix = request.files.get('dp')
            filename = pix.filename
            pix.save(myapp.config['USER_PROFILE_PATH']+filename)
            userdeets.user_pix = filename
            db.session.commit()
            flash("Profile picture updated")
            return redirect(url_for('admin_dash'))
        else:
            return render_template("admin_folder/changedp.html", dpform=dpform, userdeets=userdeets)

@myapp.route("/admin/viewconfirmed_pay/<id>", methods=["GET"])
def viewconfirmed_pay(id):
    if session.get("adminuser") == None or session.get("role") != "admin":
        return redirect(url_for('admin_login'))
    else:
        deets = db.session.query(Payments).filter(Payments.pay_id==id).first_or_404()
        return render_template("admin_folder/viewconfirmed_pay.html",deets=deets)


@myapp.route("/admin/confirmation/")
def confirmed():
    payments = Payments.query.filter_by(pay_status="Confirmed").all()
    return render_template('admin_folder/confirmed_payments.html', payments=payments)

@myapp.route("/admin/fees_records/")
def fees_records():    
    fees = db.session.query(Fees).all()
    return render_template('admin_folder/fees_records.html',fees=fees)

@myapp.route("/admin/overdue_payments/")
def overdue_payments():
    overdue_payments = StudentFees.query.join(Fees).filter(Fees.fees_duedate < current_date, StudentFees.stdfee_status != 'Paid').all()
    return render_template('admin_folder/overdue_payments.html', overdue_payments=overdue_payments)

@myapp.route("/admin/parents_records/")
def parents_records():
    parents = db.session.query(Parents).all()
    return render_template('admin_folder/parents_records.html', parents=parents)

@myapp.route("/admin/payments_records/")
def payments_records():
    payments = Payments.query.all()
    return render_template('admin_folder/payments_records.html',payments=payments)

@myapp.route("/admin/aprovepayment/<id>", methods=["GET", "POST"])
def aprove_pay(id):
    if session.get("adminuser") == None or session.get("role") != "admin":
        return redirect(url_for('admin_login'))
    else:
        if request.method == "GET":
            deets = db.session.query(Payments).filter(Payments.pay_id==id).first_or_404()
            return render_template("admin_folder/aprovepay.html",deets=deets)
        else:
            payment_2aprove = Payments.query.get(id)
            payment_2aprove.pay_status = request.form.get('status')
            if payment_2aprove.pay_status == "Confirmed":
                flash ("Payment Approve!")
            else:
                flash ("Payment Withheld", category='error')
            db.session.commit()
            return redirect("/admin/awaiting_confirmation/")


@myapp.route("/admin/students_records/")
def students_records():
    students = db.session.query(Students).all()
    links = db.session.query(Studentparent_link).all()
    return render_template('admin_folder/students_records.html', students=students)


@myapp.route("/admin/register_student/", methods=["POST","GET"])
def register_student():
    if request.method == "POST":
        # Extract Student Data
        regnumber = request.form.get("regnumber")
        dob = request.form.get("dob")
        first_name = request.form.get("firstName")
        last_name = request.form.get("lastName")
        mid_name = request.form.get("midName")
        email = request.form.get("email")
        enrrol_date = request.form.get("enrrol_date")
        campus = request.form.get("campus")
        aca_level = request.form.get("acalevel")
        aca_class = request.form.get("acaClass")
        
        # Extract Parent Data
        parents_name = request.form.get("parentsName")
        relationship = request.form.get("relationship")
        parent_email = request.form.get("parentEmail")
        parents_phone = request.form.get("parentsPhone")

        # Check if Parent Exists
        existing_parent = Parents.query.filter_by(parents_email=parent_email).first()
        
        if not existing_parent:
            # If Parent Doesn't Exist, Create a New Parent Record
             # Generate a random password
            temp_password1 = secrets.token_urlsafe(8)

            hashed_password = generate_password_hash(temp_password1, method='sha256')
            new_parent = Parents(
                parents_fullname=parents_name,
                parents_relationship=relationship,
                parents_email=parent_email,
                parents_phone=parents_phone,
                parents_pwd=hashed_password
            )
            db.session.add(new_parent)
            db.session.commit()
            parent_id = new_parent.parents_id
        else:
            parent_id = existing_parent.parents_id

        # Create Student Record
        # Generate a random password
        temp_password = secrets.token_urlsafe(8)

        hashed_passwordstd = generate_password_hash(temp_password, method='sha256')
        # Handle picture upload
        image = request.files['stdpix']
        if image:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(myapp.config['USER_PROFILE_PATH'], image_filename))
        new_student = Students(
            std_firstname=first_name,
            std_lastname=last_name,
            std_othername=mid_name,
            std_regnumber=regnumber,
            std_dob=dob,
            std_enrrodate=enrrol_date,
            std_email=email,
            std_campusid=campus,
            std_studentclassid=aca_class,
            std_studentlevelid=aca_level,
            std_pswd=hashed_passwordstd,
            std_pix=image_filename if image else None
        )
        db.session.add(new_student)
        db.session.commit()

        # Link Student to Parent
        new_link = Studentparent_link(
            stdparentlink_stdid=new_student.std_id,
            stdparentlink_parentsid=parent_id
        )
        db.session.add(new_link)
        db.session.commit()

        #sending email to new student
        msg = Message("Registration Confirmation",
                      sender="your_email@example.com",
                      recipients=[email])
        msg.body = f"Dear {first_name},\n\nYou have been successfully registered with the registration number: {regnumber}. Please keep this number safe as it will be used for all school-related tasks.\n\nThanks!\n\nYour temporary password is {temp_password}. Please change it once you login."
        mail.send(msg)

         # Send a welcome email to parent
        if not existing_parent: 
            msg = Message("Welcome to Schoolpayment",
                        sender="your_email@example.com",
                        recipients=[parent_email])
            msg.body = f"Dear {parents_name},\n\nThank you for registering. Your child, {first_name} {last_name}, has been successfully registered with the registration number: {regnumber}. Please keep this number safe as it will be used for all school-related tasks.\n\nYour temporary password is {temp_password1}. Please change it once you login."
            mail.send(msg)

        flash("Student and Parent registered successfully!", "success")
        return redirect(url_for("register_student")) # Change to your desired route
    return render_template("admin_folder/student_reg.html")


@myapp.route('/admin/register/', methods=['POST', 'GET'])
def register_admin():
    if request.method == 'GET':
        return render_template('admin_folder/reg_admin.html')
    else:
        # Fetch form data
        email = request.form['staffemail']
        staff_id = request.form['staffID']
        first_name = request.form['stafffname']
        last_name = request.form['stafflname']

        # Generate a random password
        temp_password = secrets.token_urlsafe(8)

        hashed_password = generate_password_hash(temp_password, method='sha256')

        # Handle picture upload
        image = request.files['userpix']
        if image:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(myapp.config['USER_PROFILE_PATH'], image_filename))

        # Create a new admin
        new_admin = Admin(
            admin_email=email,
            admin_password=hashed_password,
            admin_staffid=staff_id,
            admin_firstname=first_name,
            admin_lastname=last_name,
            user_pix=image_filename if image else None
        )

        db.session.add(new_admin)
        db.session.commit()

        # Send a welcome email
        msg = Message("Welcome to the Admin Dashboard",
                      sender="your_email@example.com",
                      recipients=[email])
        msg.body = f"Hello {first_name},\n\nYour temporary password is {temp_password}. Please change it once you login."
        mail.send(msg)

        flash('Admin registered successfully. Check email for temporary password.', 'success')
        return redirect(url_for('register_admin'))
    

@myapp.route('/change_password', methods=['POST',"GET"])
def change_password():
    if request.method == 'GET':
        return render_template('admin_folder/change_password.html')
    else:
        staffemail = request.form.get('staffemail')
        password = request.form.get('password')
        con_password = request.form.get('con_password')
        
        if password != con_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('admin_login')) 
        
        admin = Admin.query.filter_by(admin_email=staffemail).first()
        
        if admin:
            hashed_password = generate_password_hash(password, method='sha256')
            admin.admin_password = hashed_password
            admin.is_default_pwd = False
            db.session.commit()
            session["adminuser"] = admin.admin_id
            session["role"] = "admin"
            flash('Password Updated', 'success')
            return redirect(url_for('admin_dash')) 
        else:
            flash('Error updating password!', 'danger')
            return redirect(url_for('admin_login'))
    
        

@myapp.after_request
def after_request(response):
    #To solve the problem of loggedout user's details being cached in the browser
    response.headers["Cache-Control"] = "no-catche, no-store, must-revalidate"
    return response