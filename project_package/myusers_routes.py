import json, random, string, os, requests

from datetime import date
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps

from flask import render_template, request, abort, redirect, flash,make_response, url_for,session

from sqlalchemy.sql import text

#Local imports
from project_package import myapp, csrf
from project_package.models import *
from project_package.myforms import RegForm

current_date = date.today()

def generate_string(howmany):#call this function as gererate_string(10)
    x = random.sample(string.ascii_lowercase,howmany)
    return ''.join(x)

@myapp.route('/error')
def error_page():
    return render_template("users_folder/errorpage.html")

def login_required(f):
    @wraps(f)#this ensures that details(meta data) about the original function f, that is being decorated is still available ### we wont be needing to check if session.get('userloggedin') == None or session.get('role') != "admin"
    def login_check(*args,**kwargs):
        if session.get("userloggedin") != None:
            return f(*args,**kwargs)
        else:
            flash("Access denied")
            return redirect('/')
    return login_check 
#To use login_required, place it after the route decorator over any route that needs authentication

def login_needed(p):
    @wraps(p)#this ensures that details(meta data) about the original function f, that is being decorated is still available ### we wont be needing to check if session.get('userloggedin') == None or session.get('role') != "admin"
    def login_check(*args,**kwargs):
        if session.get("parentloggedin") != None:
            return p(*args,**kwargs)
        else:
            flash("Access denied")
            return redirect('/')
    return login_check 

@myapp.route("/dashboard/")
def users_dash():
    stdid = session.get('userloggedin')
    current_student = db.session.query(Students).get_or_404(stdid)
    return render_template("users_folder/user_dashboard.html",current_student=current_student)

@myapp.route("/")
def home_page():
    config_items=myapp.config
    return render_template("users_folder/index.html", config_items=config_items)


@myapp.route('/login', methods=['POST','GET'])
def login():
    if request.method == 'GET':
        return render_template('users_folder/index.html')
    else:
        email = request.form.get('email')
        password = request.form.get('password')

        # Check in students table
        student = Students.query.filter_by(std_email=email).first()

        if student and check_password_hash(student.std_pswd, password):
            # Check if it's their first login
            if student.is_default_pwd:
                return redirect(url_for('update_password', user_type='student', user_id=student.std_id))
            else:
                session['userloggedin']=student.std_id
                session['role']='student'
                return redirect(url_for('users_dash'))

        # If not found in students, check in parents table
        parent = Parents.query.filter_by(parents_email=email).first()

        if parent and check_password_hash(parent.parents_pwd, password):
            # Check if it's their first login
            if parent.is_default_pwd:
                return redirect(url_for('update_password', user_type='parent', user_id=parent.parents_id))
            else:
                session['parentloggedin']=parent.parents_id
                session['role']='parent'

                children = [link.link_std for link in parent.parents_deets]
                all_payments = []
                for child in children:
                    payments = Payments.query.filter_by(paystd_id=child.std_id).all()
                    all_payments.extend(payments)
                return render_template('users_folder/parent_dashboard.html',all_payments=all_payments, parent=parent)

        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))


@myapp.route('/update_password/<user_type>/<int:user_id>', methods=['GET', 'POST'])
def update_password(user_type, user_id):
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        conf_password = request.form.get('conf_password')

        if conf_password != new_password:
            flash("New password and confirm password must match", category='error')
            return render_template('users_folder/index.html')
        else:
            if user_type == 'student':
                student = Students.query.get(user_id)
                student.std_pswd = generate_password_hash(new_password, method='sha256')
                student.is_default_pwd = False
                db.session.commit()
                session['userloggedin']=student.std_id
                session['role']='student'
                flash('Password changed successfully!', 'success')
                return redirect(url_for('users_dash'))
            
            elif user_type == 'parent':
                parent = Parents.query.get(user_id)
                parent.parents_pwd = generate_password_hash(new_password, method='sha256')
                parent.is_default_pwd = False
                db.session.commit()
                session['parentloggedin']=parent.parents_id
                session['role']='parent'
                flash('Password changed successfully!', 'success')
                return redirect(url_for('parent_dashboard'))
        
    return render_template('users_folder/update_password.html')

@myapp.route('/parent_dashboard/')
@login_needed
def parent_dashboard():
    parent_id=session.get('parentloggedin')
    parent = Parents.query.get(parent_id)

    children = [link.link_std for link in parent.parents_deets]
    outstanding_fees = []
    for child in children:
        unpaid_fees = StudentFees.query.filter_by(stdfee_std_id=child.std_id, stdfee_status='Unpaid').all()
        outstanding_fees.extend(unpaid_fees)

    overdue_fees = []
    unpaid_fees_for_child = StudentFees.query.filter_by(stdfee_std_id=child.std_id, stdfee_status="Unpaid").all()
    for std_fee in unpaid_fees_for_child:
        # Check if the fee's due date is in the past and it's not marked as paid or waived
        if std_fee.associated_fee.fees_duedate < current_date:
            overdue_fees.append(std_fee)

    all_payments = []
    
    for child in children:
        payments = Payments.query.filter_by(paystd_id=child.std_id).all()
        all_payments.extend(payments)
    return render_template('users_folder/parent_dashboard.html', parent=parent, all_payments=all_payments, children=children, outstanding_fees=outstanding_fees, overdue_fees=overdue_fees)

@myapp.route('/parent/enrolled_children/')
@login_needed
def enrolled():
    parent_id=session.get('parentloggedin')
    parent = Parents.query.get(parent_id)

    children = [link.link_std for link in parent.parents_deets]
    return render_template('users_folder/enrolled_children.html', children=children, parent=parent)

@myapp.route('/parent/outsanding_fees')
@login_needed
def parentoutstanding():
    parent_id=session.get('parentloggedin')
    parent = Parents.query.get(parent_id)

    children = [link.link_std for link in parent.parents_deets]
    outstanding_fees = []
    for child in children:
        unpaid_fees = StudentFees.query.filter_by(stdfee_std_id=child.std_id, stdfee_status='Unpaid').all()
        outstanding_fees.extend(unpaid_fees)
    return render_template('users_folder/parent_outstanding.html', outstanding_fees=outstanding_fees, parent=parent)

@myapp.route('/parent/payment_records')
@login_needed
def parentpayment_record():
    parent_id=session.get('parentloggedin')
    parent = Parents.query.get(parent_id)

    children = [link.link_std for link in parent.parents_deets]
    all_payments = []
    for child in children:
        payments = Payments.query.filter_by(paystd_id=child.std_id).all()
        all_payments.extend(payments)
    return render_template('users_folder/parentpayment_records.html', all_payments=all_payments, parent=parent)

@myapp.route('/parent/fee_records')
@login_needed
def parentfee_record():
    parent_id=session.get('parentloggedin')
    parent = Parents.query.get(parent_id)

    children = [link.link_std for link in parent.parents_deets]
    all_fees = []
    for child in children:
        fees = StudentFees.query.filter_by(stdfee_std_id=child.std_id).all()
        all_fees.extend(fees)
    return render_template('users_folder/parentfees_record.html', all_fees=all_fees, parent=parent)

@myapp.context_processor
def inject_student_name():
    student_id = session.get("userloggedin")
    if student_id:
        student = Students.query.get(student_id)
        if student:
            return {'current_student':student}
    return {}

@myapp.route("/logout")
def logout():
    if session.get('userloggedin') != None:
        session.pop('userloggedin',None)
        flash("Your are logged out", category="INFO")
        return redirect('/')
    else:
        return redirect(url_for('login'))
    
@myapp.route("/parent/logout")
def parentlogout():
    if session.get('parentloggedin') != None:
        session.pop('parentloggedin',None)
        flash("Your are logged out", category="INFO")
        return redirect('/')
    else:
        return redirect(url_for('login'))


@myapp.route("/fees_record")
def fees_record():
    user_id = session.get("userloggedin")
    fees = StudentFees.query.filter_by(stdfee_std_id=user_id).all()
    return render_template("users_folder/fees_record.html",fees=fees)

@myapp.route("/payment_record")
def payment_record():
    user_id = session.get("userloggedin")
    payments = Payments.query.filter_by(paystd_id=user_id).all()
    return render_template("users_folder/payment_records.html",payments=payments)

@myapp.route("/outstanding")
def outstanding():
    user_id = session.get("userloggedin")
    fees = StudentFees.query.filter_by(stdfee_std_id=user_id,stdfee_status="Unpaid").all()
    return render_template("users_folder/outstanding.html",fees=fees)

@myapp.after_request
def after_request(response):
    #To solve the problem of loggedout user's details being cached in the browser
    response.headers["Cache-Control"] = "no-catche, no-store, must-revalidate"
    return response 


@myapp.route("/dashboard")
@login_required
def dashboard():
    if session.get('userloggedin') != None: #This is to prevent users from entering (/dashboard) on the browser to access dashbord
                                    # directly without logging in
        user_id = session.get("userloggedin")
        payments = Payments.query.filter_by(paystd_id=user_id).limit(3).all()
        outstandingfees = StudentFees.query.filter_by(stdfee_std_id=user_id,stdfee_status="Unpaid").all()
        overdue_payments = StudentFees.query.join(Fees).filter(Fees.fees_duedate < current_date, StudentFees.stdfee_status != 'Paid', StudentFees.stdfee_std_id==user_id).all()
        return render_template("users_folder/user_dashboard.html", payments=payments, overdue_payments=overdue_payments, outstandingfees=outstandingfees)
    else:
        flash("You must be logged in to view this page", category="error")
        return redirect('/')
    
@myapp.route("/make_payment/", methods=["POST", "GET"])
def make_payment():
    if request.method == 'GET':
        user_id = session.get("userloggedin")
        unpaid = StudentFees.query.filter_by(stdfee_std_id=user_id, stdfee_status='Unpaid').all()
        return render_template("users_folder/make_payment.html", unpaid=unpaid)
    else:
        fees_to_pay = request.form.get('fee_to_pay')
        payment_method = request.form.get('payment_method')
        session['feeselected'] = fees_to_pay
        ref_no = generate_string(12)
        session['ref_no'] = ref_no

        if fees_to_pay == "":
            flash("No fee selected!!!. Please select a fee from the drop down.", category="error")
            return redirect(url_for("make_payment"))
        else:
            if payment_method == 'card':
                return redirect(url_for("card_confirmation"))
            elif payment_method == 'bank_transfer':
                return redirect(url_for("transfer_confirmation"))
            elif payment_method == 'cash_deposit':
                return redirect(url_for("deposit_confirmation"))
            else:
                flash("Invalid payment method selected.", category="error")
                return redirect(url_for("make_payment"))
            
@myapp.route("/parent/make_payment/", methods=["POST", "GET"])
@login_needed
def parentmake_payment():
    if request.method == 'GET':
        parent_id=session.get('parentloggedin')
        parent = Parents.query.get(parent_id)

        children = [link.link_std for link in parent.parents_deets]
        outstanding_fees = []
        for child in children:
            unpaid_fees = StudentFees.query.filter_by(stdfee_std_id=child.std_id, stdfee_status='Unpaid').all()
            outstanding_fees.extend(unpaid_fees)
        return render_template("users_folder/parentmake_payment.html", outstanding_fees=outstanding_fees, parent=parent)
    else:
        fees_to_pay = request.form.get('fee_to_pay')
        payment_method = request.form.get('payment_method')
        session['feeselected'] = fees_to_pay
        ref_no = generate_string(12)
        session['ref_no'] = ref_no

        if fees_to_pay == "":
            flash("No fee selected!!!. Please select a fee from the drop down.", category="error")
            return redirect(url_for("parentmake_payment"))
        else:
            if payment_method == 'card':
                return redirect(url_for("parentcard_confirmation"))
            elif payment_method == 'bank_transfer':
                return redirect(url_for("parenttransfer_confirmation"))
            elif payment_method == 'cash_deposit':
                return redirect(url_for("parentdeposit_confirmation"))
            else:
                flash("Invalid payment method selected.", category="error")
                return redirect(url_for("parentmake_payment"))

@myapp.route("/card_confirmation",methods=['POST','GET'])
@login_required
def card_confirmation():
    if session.get('ref_no')==None: #when visited directly
        flash('please complete the form', category='error')
        return render_template("users_folder/make_payment.html")
    else:
        selected_fee_id = session.get('feeselected')
        selected_fee = StudentFees.query.get(selected_fee_id)
        ref_no = session.get('ref_no', 'REF_NOT_FOUND')  # Replace 'REF_NOT_FOUND' with an appropriate fallback    
        return render_template('users_folder/card_confirmation.html', ref_no=ref_no,selected_fee=selected_fee)

@myapp.route("/parent/card_confirmation",methods=['POST','GET'])
@login_needed
def parentcard_confirmation():
    parent_id=session.get('parentloggedin')
    parent = Parents.query.get(parent_id)
    if session.get('ref_no')==None: #when visited directly
        flash('please complete the form', category='error')
        return render_template("users_folder/parentmake_payment.html", parent=parent)
    else:
        selected_fee_id = session.get('feeselected')
        selected_fee = StudentFees.query.get(selected_fee_id)
        ref_no = session.get('ref_no', 'REF_NOT_FOUND')  # Replace 'REF_NOT_FOUND' with an appropriate fallback    
        return render_template('users_folder/parentcard_confirmation.html', ref_no=ref_no,selected_fee=selected_fee, parent=parent)
    

@myapp.route("/initialize/paystack/")
def initialize_paystack():
    userid = session.get('userloggedin')
    deets = Students.query.get(userid)    
    refno = session.get('ref_no')
    selected_fee_id = session.get('feeselected')
    selected_fee = StudentFees.query.get(selected_fee_id)
        
    url="https://api.paystack.co/transaction/initialize"
    
    headers = {"Content-Type": "application/json","Authorization":"Bearer sk_test_5eaa1de978b683d6edb8286a46023fa06d8ebbd1"}
    data={"email":deets.std_email, "amount":selected_fee.stdfee_amount,"reference":refno}
    response = requests.post(url,headers=headers,data=json.dumps(data))   
    rspjson = response.json()    
    if rspjson['status'] == True:
        redirectURL = rspjson['data']['authorization_url']
        return redirect(redirectURL)
    
    else:
        flash("Please complete the form again")
        return redirect('/make_payment/')
    

@myapp.route("/parent/initialize/paystack/")
def parentinitialize_paystack():
    parentid = session.get('parentloggedin')
    deets = Parents.query.get(parentid)    
    refno = session.get('ref_no')
    selected_fee_id = session.get('feeselected')
    selected_fee = StudentFees.query.get(selected_fee_id)
        
    url="https://api.paystack.co/transaction/initialize"
    
    headers = {"Content-Type": "application/json","Authorization":"Bearer sk_test_5eaa1de978b683d6edb8286a46023fa06d8ebbd1"}
    data={"email":deets.parents_email, "amount":selected_fee.stdfee_amount,"reference":refno}
    response = requests.post(url,headers=headers,data=json.dumps(data))   
    rspjson = response.json()    
    if rspjson['status'] == True:
        redirectURL = rspjson['data']['authorization_url']
        return redirect(redirectURL)
    
    else:
        flash("Please complete the form again")
        return redirect('/parentmake_payment/')
    

@myapp.route("/landing")
def landing_page():
     refno = session.get('ref_no')
     selected_fee_id = session.get('feeselected')
     selected_fee = StudentFees.query.get(selected_fee_id)
     url="https://api.paystack.co/transaction/verify/"+refno
     headers = {"Content-Type": "application/json","Authorization":"Bearer sk_test_5eaa1de978b683d6edb8286a46023fa06d8ebbd1"}
     response = requests.get(url,headers=headers)
     rspjson = json.loads(response.text)

     if rspjson['status'] == True:
        paystatus = rspjson['data']['gateway_response']
        pay_date = current_date
        ref_no = session.get('ref_no')
        stdid = selected_fee.associated_student.std_id
        primary_parent = Students.query.get(stdid).students_deets[0].link_parents

        # Add payment details to Payments model
        payment = Payments(
            pay_date=pay_date,
            pay_amount=selected_fee.stdfee_amount,
            paystd_id=selected_fee.stdfee_std_id,
            pay_method="Card",
            pay_ref=ref_no,
            pay_verify_deet="PayPal",
            payparent_id = primary_parent.parents_id,
            pay_stdfee_id = selected_fee.stdfee_id

        )
        db.session.add(payment)

        # Update StudentFees status
        selected_fee.stdfee_status = "Pending"
        db.session.commit()

        session.pop('ref_no',None)
        session.pop('feeselected',None)
        flash("Payment Successful", category="success")
        if session.get('userloggedin') != None:
            return redirect(url_for("dashboard"))
        else:
            return redirect(url_for("parent_dashboard"))

    
     else:        
        flash("Payment Failed", category="error")
        if session.get('userloggedin') != None:
            return redirect(url_for("dashboard"))
        else:
            return redirect(url_for("parent_dashboard"))


@myapp.route("/deposit_confirmation",methods=['POST','GET'])
@login_required
def deposit_confirmation():
    if request.method == 'GET':
        selected_fee_id = session.get('feeselected')
        selected_fee = StudentFees.query.get(selected_fee_id)
        ref_no = session.get('ref_no', 'REF_NOT_FOUND')  # Replace 'REF_NOT_FOUND' with an appropriate fallback
        return render_template("users_folder/deposit_confirmation.html", ref_no=ref_no,selected_fee=selected_fee)
    else:
        selected_fee_id = session.get('feeselected')
        if not selected_fee_id:
            flash('Fee selection not found. Please start again.', category='error')
            return redirect(url_for("make_payment"))

        selected_fee = StudentFees.query.get(selected_fee_id)
        if not selected_fee:
            flash('Fee details not found. Please start again.', category='error')
            return redirect(url_for("make_payment"))

        account_holder = request.form.get("tellerno")
        pay_date = request.form.get("paydate")
        ref_no = session.get('ref_no')
        stdid = selected_fee.associated_student.std_id
        primary_parent = Students.query.get(stdid).students_deets[0].link_parents

        # Add payment details to Payments model
        payment = Payments(
            pay_date=pay_date,
            pay_amount=selected_fee.stdfee_amount,
            paystd_id=selected_fee.stdfee_std_id,
            pay_method="Cash Deposite",
            pay_ref=ref_no,
            pay_verify_deet=account_holder,
            payparent_id = primary_parent.parents_id,
            pay_stdfee_id = selected_fee.stdfee_id

        )
        db.session.add(payment)

        # Update StudentFees status
        selected_fee.stdfee_status = "Pending"
        db.session.commit()

        session.pop('ref_no',None)
        session.pop('feeselected',None)

        flash("Payment Successful", category="success")
        return redirect(url_for("dashboard"))
    


@myapp.route("/parent/deposit_confirmation",methods=['POST','GET'])
@login_needed
def parentdeposit_confirmation():
    if request.method == 'GET':
        parent_id=session.get('parentloggedin')
        parent = Parents.query.get(parent_id)
        selected_fee_id = session.get('feeselected')
        selected_fee = StudentFees.query.get(selected_fee_id)
        ref_no = session.get('ref_no', 'REF_NOT_FOUND')  # Replace 'REF_NOT_FOUND' with an appropriate fallback
        return render_template("users_folder/parentdeposit_confirmation.html", ref_no=ref_no,selected_fee=selected_fee, parent=parent)
    else:
        selected_fee_id = session.get('feeselected')
        if not selected_fee_id:
            flash('Fee selection not found. Please start again.', category='error')
            return redirect(url_for("parentmake_payment"))

        selected_fee = StudentFees.query.get(selected_fee_id)
        if not selected_fee:
            flash('Fee details not found. Please start again.', category='error')
            return redirect(url_for("parentmake_payment"))

        account_holder = request.form.get("tellerno")
        pay_date = request.form.get("paydate")
        ref_no = session.get('ref_no')
        stdid = selected_fee.associated_student.std_id
        primary_parent = Students.query.get(stdid).students_deets[0].link_parents

        # Add payment details to Payments model
        payment = Payments(
            pay_date=pay_date,
            pay_amount=selected_fee.stdfee_amount,
            paystd_id=selected_fee.stdfee_std_id,
            pay_method="Cash Deposite",
            pay_ref=ref_no,
            pay_verify_deet=account_holder,
            payparent_id = primary_parent.parents_id,
            pay_stdfee_id = selected_fee.stdfee_id

        )
        db.session.add(payment)

        # Update StudentFees status
        selected_fee.stdfee_status = "Pending"
        db.session.commit()

        session.pop('ref_no',None)
        session.pop('feeselected',None)

        flash("Payment Successful", category="success")
        return redirect(url_for("parent_dashboard"))
    

@myapp.route("/transfer_confirmation", methods=['POST', 'GET'])
@login_required
def transfer_confirmation():
    if request.method == 'GET':
        selected_fee_id = session.get('feeselected')
        selected_fee = StudentFees.query.get(selected_fee_id)
        ref_no = session.get('ref_no', 'REF_NOT_FOUND')  # Replace 'REF_NOT_FOUND' with an appropriate fallback
        return render_template("users_folder/transfer_confirmation.html", ref_no=ref_no,selected_fee=selected_fee)
    else:
        selected_fee_id = session.get('feeselected')
        if not selected_fee_id:
            flash('Fee selection not found. Please start again.', category='error')
            return redirect(url_for("make_payment"))

        selected_fee = StudentFees.query.get(selected_fee_id)
        if not selected_fee:
            flash('Fee details not found. Please start again.', category='error')
            return redirect(url_for("make_payment"))

        account_holder = request.form.get("accname")
        pay_date = request.form.get("paydate")
        ref_no = session.get('ref_no')
        stdid = selected_fee.associated_student.std_id
        primary_parent = Students.query.get(stdid).students_deets[0].link_parents

        # Add payment details to Payments model
        payment = Payments(
            pay_date=pay_date,
            pay_amount=selected_fee.stdfee_amount,
            paystd_id=selected_fee.stdfee_std_id,
            pay_method="Bank Transfer",
            pay_ref=ref_no,
            pay_verify_deet=account_holder,
            payparent_id = primary_parent.parents_id,
            pay_stdfee_id = selected_fee.stdfee_id

        )
        db.session.add(payment)

        # Update StudentFees status
        selected_fee.stdfee_status = "Pending"
        db.session.commit()

        session.pop('ref_no',None)
        session.pop('feeselected',None)

        flash("Payment Successful", category="success")
        return redirect(url_for("dashboard"))



@myapp.route("/parent/transfer_confirmation", methods=['POST', 'GET'])
@login_needed
def parenttransfer_confirmation():
    if request.method == 'GET':
        parent_id=session.get('parentloggedin')
        parent = Parents.query.get(parent_id)
        selected_fee_id = session.get('feeselected')
        selected_fee = StudentFees.query.get(selected_fee_id)
        ref_no = session.get('ref_no', 'REF_NOT_FOUND')  # Replace 'REF_NOT_FOUND' with an appropriate fallback
        return render_template("users_folder/parenttransfer_confirmation.html", ref_no=ref_no,selected_fee=selected_fee, parent=parent)
    else:
        selected_fee_id = session.get('feeselected')
        if not selected_fee_id:
            flash('Fee selection not found. Please start again.', category='error')
            return redirect(url_for("parentmake_payment"))

        selected_fee = StudentFees.query.get(selected_fee_id)
        if not selected_fee:
            flash('Fee details not found. Please start again.', category='error')
            return redirect(url_for("parentmake_payment"))

        account_holder = request.form.get("accname")
        pay_date = request.form.get("paydate")
        ref_no = session.get('ref_no')
        stdid = selected_fee.associated_student.std_id
        primary_parent = Students.query.get(stdid).students_deets[0].link_parents

        # Add payment details to Payments model
        payment = Payments(
            pay_date=pay_date,
            pay_amount=selected_fee.stdfee_amount,
            paystd_id=selected_fee.stdfee_std_id,
            pay_method="Bank Transfer",
            pay_ref=ref_no,
            pay_verify_deet=account_holder,
            payparent_id = primary_parent.parents_id,
            pay_stdfee_id = selected_fee.stdfee_id

        )
        db.session.add(payment)

        # Update StudentFees status
        selected_fee.stdfee_status = "Pending"
        db.session.commit()

        session.pop('ref_no',None)
        session.pop('feeselected',None)

        flash("Payment Successful", category="success")
        return redirect(url_for("parent_dashboard"))
    

@myapp.after_request
def after_request(response):
    #To solve the problem of loggedout user's details being cached in the browser
    response.headers["Cache-Control"] = "no-catche, no-store, must-revalidate"
    return response

        
