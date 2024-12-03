from flask import Flask, session, render_template, redirect, url_for, make_response, request, Blueprint
from flask_session import Session
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import x
import uuid 
import time
import redis
import os

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)

app = Flask(__name__, static_folder="static")
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', etc.
Session(app)


# app.secret_key = "your_secret_key"

##############################
##############################
##############################

def _________GET_________(): pass

##############################
##############################

##############################
@app.get("/test-set-redis")
def view_test_set_redis():
    redis_host = "redis"
    redis_port = 6379
    redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)    
    redis_client.set("name", "Santiago", ex=10)
    # name = redis_client.get("name")
    return "name saved"

@app.get("/test-get-redis")
def view_test_get_redis():
    redis_host = "redis"
    redis_port = 6379
    redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)    
    name = redis_client.get("name")
    if not name: name = "no name"
    return name

##############################
@app.get("/")
def view_index():
    # make a variable that contains all users that has the role restaurant in the database and pass it to the template 
    db, cursor = x.db()
    q = """ SELECT * FROM users 
            JOIN users_roles 
            ON user_pk = user_role_user_fk 
            JOIN roles
            ON role_pk = user_role_role_fk
            WHERE role_name = 'restaurant'"""
    cursor.execute(q)
    restaurant_users = cursor.fetchall()
    q = """ SELECT * FROM food_categories"""
    cursor.execute(q)
    food_categories = cursor.fetchall()
    cursor.close()
    db.close()
    user = session.get("user")
    return render_template("view_index.html", user=user, restaurant_users=restaurant_users, food_categories=food_categories)

##############################
@app.get("/signup")
@x.no_cache
def view_signup():  
    ic(session)
    if session.get("user"):
        if len(session.get("user").get("roles")) > 1:
            return redirect(url_for("view_choose_role")) 
        if "admin" in session.get("user").get("roles"):
            return redirect(url_for("view_admin"))
        if "customer" in session.get("user").get("roles"):
            return redirect(url_for("view_customer")) 
        if "partner" in session.get("user").get("roles"):
            return redirect(url_for("view_partner"))         
    return render_template("view_signup.html", x=x, title="Signup")


##############################
@app.get("/login")
@x.no_cache
def view_login():  
    # ic("#"*20, "VIEW_LOGIN")
    ic(session)
    # print(session, flush=True)  
    if session.get("user"):
        if len(session.get("user").get("roles")) > 1:
            return redirect(url_for("view_choose_role")) 
        if "admin" in session.get("user").get("roles"):
            return redirect(url_for("view_admin"))
        if "customer" in session.get("user").get("roles"):
            return redirect(url_for("view_customer")) 
        if "partner" in session.get("user").get("roles"):
            return redirect(url_for("view_partner"))         
    return render_template("view_login.html", x=x, title="Login", message=request.args.get("message", ""))


##############################
@app.get("/customer")
@x.no_cache
def view_customer():
    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    user = session.get("user")
    if len(user.get("roles", "")) > 1:
        return redirect(url_for("view_choose_role"))
    return render_template("view_customer.html", user=user)

##############################
@app.get("/partner")
@x.no_cache
def view_partner():
    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    user = session.get("user")
    if len(user.get("roles", "")) > 1:
        return redirect(url_for("view_choose_role"))
    return "x"


##############################
@app.get("/admin")
@x.no_cache
def view_admin():
    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    user = session.get("user")
    if not "admin" in user.get("roles", ""):
        return redirect(url_for("view_login"))
    return render_template("view_admin.html")



##############################
@app.get("/choose-role")
@x.no_cache
def view_choose_role():
    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    if not len(session.get("user").get("roles")) >= 2:
        return redirect(url_for("view_login"))
    user = session.get("user")
    return render_template("view_choose_role.html", user=user, title="Choose role")

##############################
@app.get("/<user_pk>/items")
def view_restaurant_items(user_pk):
    # make a variable that contains all users that has the role restaurant in the database and pass it to the template 
    random_image = request.args.get("image", default=None)
    db, cursor = x.db()
    q = """ SELECT * FROM items 
            WHERE item_user_fk = %s
            """

    cursor.execute(q, (user_pk,))
    restaurant_items = cursor.fetchall()
    q = """ SELECT * FROM users WHERE user_pk = %s"""
    cursor.execute(q, (user_pk,))
    restaurant_user = cursor.fetchone()
    cursor.close()
    db.close()
    user = session.get("user")
    return render_template("view_restaurant_items.html", user=user, restaurant_items=restaurant_items, restaurant_user=restaurant_user, random_image=random_image)

##############################
@app.get("/restaurant/<food_category_pk>")
def view_restaurant_by_category(food_category_pk):
    # make a variable that contains all users that has the role restaurant in the database and pass it to the template 

    db, cursor = x.db()
    q = """ SELECT * FROM users
            JOIN restaurant_food_category
            ON user_pk = restaurant_food_category_user_fk
            WHERE restaurant_food_category_food_category_fk = %s 
            """

    cursor.execute(q, (food_category_pk,))
    restaurants = cursor.fetchall()
    q = """ SELECT * FROM food_categories WHERE food_category_pk = %s"""
    cursor.execute(q, (food_category_pk,))
    food_category = cursor.fetchone()
    cursor.close()
    db.close()
    user = session.get("user")
    return render_template("view_restaurant_by_category.html", user=user, restaurants=restaurants, food_category=food_category)
##############################
##############################
##############################

def _________POST_________(): pass

##############################
##############################
##############################

@app.post("/logout")
def logout():
    # ic("#"*30)
    # ic(session)
    session.pop("user", None)
    # session.clear()
    # session.modified = True
    # ic("*"*30)
    # ic(session)
    return redirect(url_for("view_login"))


##############################
@app.post("/users")
@x.no_cache
def signup():
    try:
        user_name = x.validate_user_name()
        user_last_name = x.validate_user_last_name()
        user_email = x.validate_user_email()
        user_password = x.validate_user_password()
        hashed_password = generate_password_hash(user_password)
        
        user_pk = str(uuid.uuid4())
        user_avatar = ""
        user_created_at = int(time.time())
        user_deleted_at = 0
        user_blocked_at = 0
        user_updated_at = 0
        user_verified_at = 0
        user_verification_key = str(uuid.uuid4())

        db, cursor = x.db()
        q = 'INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
        cursor.execute(q, (user_pk, user_name, user_last_name, user_email, 
                           hashed_password, user_avatar, user_created_at, user_deleted_at, user_blocked_at, 
                           user_updated_at, user_verified_at, user_verification_key))
        
        

        x.send_verify_email(user_email, user_verification_key)
        db.commit()

        q = "INSERT INTO users_roles VALUES(%s, %s)"
        cursor.execute(q,(user_pk, x.CUSTOMER_ROLE_PK))
    
        db.commit()
        return """<template mix-redirect="/login"></template>""", 201
    
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "users.user_email" in str(ex): 
                toast = render_template("___toast.html", message="email not available")
                return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
            return f"""<template mix-target="#toast" mix-bottom>System upgrading</template>""", 500        
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################

login = Blueprint("login", __name__)

##############################
@app.post("/login")
def login():
    try:
        # Detailed logging of input validation
        user_email = x.validate_user_email()
        user_password = x.validate_user_password()

        print("Validated Email:", repr(user_email))  # Use repr to show exact string
        print("Validated Password Length:", len(user_password))

        db, cursor = x.db()

        # Modified query with more flexible matching
        q = """
            SELECT * FROM users
            JOIN users_roles ON user_pk = user_role_user_fk
            JOIN roles ON role_pk = user_role_role_fk
            WHERE LOWER(TRIM(user_email)) = LOWER(TRIM(%s))
        """
        cursor.execute(q, (user_email,))
        rows = cursor.fetchall()

        print("Number of rows found:", len(rows))
        if rows:
            print("Found user details:", rows[0])
        else:
            print("No user found with email:", user_email)

        # Rest of your existing code...

        if not rows:
            toast = render_template("___toast.html", message="user not registered")
            return f"""<template mix-target="#toast">{toast}</template>""", 400     
        if not check_password_hash(rows[0]["user_password"], user_password):
            toast = render_template("___toast.html", message="invalid credentials")
            return f"""<template mix-target="#toast">{toast}</template>""", 401
        
        roles = []
        for row in rows:
            roles.append(row["role_name"])
        user = {
            "user_pk": rows[0]["user_pk"],
            "user_name": rows[0]["user_name"],
            "user_last_name": rows[0]["user_last_name"],
            "user_email": rows[0]["user_email"],
            "roles": roles
        }
        ic(user)

        session["user"] = user

        if len(roles) == 1:
            return f"""<template mix-redirect="/{roles[0]}"></template>"""
        return f"""<template mix-redirect="/choose-role"></template>"""
        # db.commit()
    
    except Exception as ex:

        ic(ex)
        if "db" in locals(): db.rollback()

        # My own exception
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        
        # Database exception
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "users.user_email" in str(ex):
                return """<template mix-target="#toast" mix-bottom>email not available</template>""", 400
            return "<template>System upgrading</template>", 500  
      
        # Any other exception
        return """<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500  
    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()





##############################
# @app.post("/login")
# def login():
#     try:

#         user_email = x.validate_user_email()
#         user_password = x.validate_user_password()

#         db, cursor = x.db()
#         q = """ SELECT * FROM users 
#                 JOIN users_roles 
#                 ON user_pk = user_role_user_fk 
#                 JOIN roles
#                 ON role_pk = user_role_role_fk
#                 WHERE user_email = %s"""
#         cursor.execute(q, (user_email,))
#         rows = cursor.fetchall()
#         ic(rows)
#         if not rows:
#             toast = render_template("___toast.html", message="user not registered")
#             return f"""<template mix-target="#toast">{toast}</template>""", 400     
#         if not check_password_hash(rows[0]["user_password"], user_password):
#             toast = render_template("___toast.html", message="invalid credentials")
#             return f"""<template mix-target="#toast">{toast}</template>""", 401
#         roles = []
#         for row in rows:
#             roles.append(row["role_name"])
#         user = {
#             "user_pk": rows[0]["user_pk"],
#             "user_name": rows[0]["user_name"],
#             "user_last_name": rows[0]["user_last_name"],
#             "user_email": rows[0]["user_email"],
#             "roles": roles
#         }
#         ic(user)
#         session["user"] = user
#         if len(roles) == 1:
#             return f"""<template mix-redirect="/{roles[0]}"></template>"""
#         return f"""<template mix-redirect="/choose-role"></template>"""
#     except Exception as ex:
#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException): 
#             toast = render_template("___toast.html", message=ex.message)
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             return "<template>System upgrating</template>", 500        
#         return "<template>System under maintenance</template>", 500  
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()


##############################
@app.post("/items")
def create_item():
    try:
        # TODO: validate item_title, item_description, item_price
        file, item_image_name = x.validate_item_image()

        # Save the image
        file.save(os.path.join(x.UPLOAD_ITEM_FOLDER, item_image_name))
        # TODO: if saving the image went wrong, then rollback by going to the exception
        # TODO: Success, commit
        return item_image_name
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrating</template>", 500        
        return "<template>System under maintenance</template>", 500  
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()    


##############################
##############################
##############################

def _________PUT_________(): pass

##############################
##############################
##############################

@app.put("/users")
def user_update():
    try:
        if not session.get("user"): x.raise_custom_exception("please login", 401)

        user_pk = session.get("user").get("user_pk")
        user_name = x.validate_user_name()
        user_last_name = x.validate_user_last_name()
        user_email = x.validate_user_email()

        user_updated_at = int(time.time())

        db, cursor = x.db()
        q = """ UPDATE users
                SET user_name = %s, user_last_name = %s, user_email = %s, user_updated_at = %s
                WHERE user_pk = %s
            """
        cursor.execute(q, (user_name, user_last_name, user_email, user_updated_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot update user", 401)
        db.commit()
        return """<template>user updated</template>"""
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            if "users.user_email" in str(ex): return "<template>email not available</template>", 400
            return "<template>System upgrating</template>", 500        
        return "<template>System under maintenance</template>", 500    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.put("/users/block/<user_pk>")
def user_block(user_pk):
    try:        
        if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
        user_pk = x.validate_uuid4(user_pk)
        user_blocked_at = int(time.time())
        db, cursor = x.db()
        q = 'UPDATE users SET user_blocked_at = %s WHERE user_pk = %s'
        cursor.execute(q, (user_blocked_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot block user", 400)
        db.commit()
        return """<template>user blocked</template>"""
    
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code        
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500        
        return "<template>System under maintenance</template>", 500  
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.put("/users/unblock/<user_pk>")
def user_unblock(user_pk):
    try:
        if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
        user_pk = x.validate_uuid4(user_pk)
        user_blocked_at = 0
        db, cursor = x.db()
        q = 'UPDATE users SET user_blocked_at = %s WHERE user_pk = %s'
        cursor.execute(q, (user_blocked_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot unblock user", 400)
        db.commit()
        return """<template>user unblocked</template>"""
    
    except Exception as ex:

        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code        
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500        
        return "<template>System under maintenance</template>", 500  
    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()




##############################
##############################
##############################

def _________DELETE_________(): pass

##############################
##############################
##############################


@app.delete("/users/<user_pk>")
def user_delete(user_pk):
    try:
        # Check if user is logged
        if not session.get("user", ""): return redirect(url_for("view_login"))
        # Check if it is an admin
        if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
        user_pk = x.validate_uuid4(user_pk)
        user_deleted_at = int(time.time())
        db, cursor = x.db()
        q = 'UPDATE users SET user_deleted_at = %s WHERE user_pk = %s'
        cursor.execute(q, (user_deleted_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot delete user", 400)
        db.commit()
        return """<template>user deleted</template>"""
    
    except Exception as ex:

        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code        
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500        
        return "<template>System under maintenance</template>", 500  
    
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()




##############################
##############################
##############################

def _________BRIDGE_________(): pass

##############################
##############################
##############################


##############################
@app.get("/verify/<verification_key>")
@x.no_cache
def verify_user(verification_key):
    try:
        ic(verification_key)
        verification_key = x.validate_uuid4(verification_key)
        user_verified_at = int(time.time())

        db, cursor = x.db()
        q = """ UPDATE users 
                SET user_verified_at = %s 
                WHERE user_verification_key = %s"""
        cursor.execute(q, (user_verified_at, verification_key))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot verify account", 400)
        db.commit()
        return redirect(url_for("view_login", message="User verified, please login"))

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): return ex.message, ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "Database under maintenance", 500        
        return "System under maintenance", 500  
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()    






