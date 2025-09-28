"""Authentication blueprint for SAML and session management."""

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..auth.session import (
    create_session,
    destroy_session,
    get_current_user,
    is_authenticated,
)
from ..models import AuditAction, AuditLog, AuditResult, AuthMethod, User, UserRole

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login")
def login():
    """Display login page or redirect to SAML."""
    if "user_id" in session:
        return redirect(url_for("main.index"))

    return render_template("auth/login.html")


@auth_bp.route("/saml/login")
def saml_login():
    """Initiate SAML login process."""
    # In a real implementation, this would redirect to the SAML IdP
    # For now, we'll simulate SAML login
    flash("SAML authentication not yet implemented. Using demo login.", "warning")
    return redirect(url_for("auth.demo_login"))


@auth_bp.route("/database/login", methods=["GET", "POST"])
def database_login():
    """Database authentication login."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("auth/database_login.html")

        # Find user by username or email
        user = User.find_by_username(username) or User.find_by_email(username)

        if not user:
            flash("Invalid username or password", "error")
            return render_template("auth/database_login.html")

        # Check if user uses database authentication
        if user.auth_method != AuthMethod.DATABASE:
            flash("This account does not use database authentication", "error")
            return render_template("auth/database_login.html")

        # Verify password
        if not user.check_password(password):
            flash("Invalid username or password", "error")
            return render_template("auth/database_login.html")

        # Check if user is active
        if not user.is_active:
            flash("Account is disabled. Contact administrator.", "error")
            return render_template("auth/database_login.html")

        # Check email verification (if required)
        if (
            current_app.config.get("REQUIRE_EMAIL_VERIFICATION", True)
            and not user.email_verified
        ):
            flash(
                "Email verification required. Please check your email for verification link.",
                "warning",
            )
            return redirect(url_for("auth.resend_verification", user_id=user.id))

        # Check if password change is required
        if user.must_change_password:
            # Store user ID in session temporarily for password change
            session["password_change_user_id"] = user.id
            flash("You must change your password before continuing", "warning")
            return redirect(url_for("auth.change_password"))

        # Create session
        session_token = create_session(user, request.remote_addr)

        # Log the login
        AuditLog.log_user_action(
            action=AuditAction.LOGIN,
            result=AuditResult.SUCCESS,
            user=user,
            ip_address=request.remote_addr,
            session_id=session_token,
        )

        flash(f"Welcome back, {user.full_name}!", "success")
        return redirect(url_for("main.index"))

    return render_template("auth/database_login.html")


@auth_bp.route("/database/register", methods=["GET", "POST"])
def database_register():
    """Database authentication registration."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        full_name = request.form.get("full_name", "").strip()

        # Validation
        if not all([username, email, password, confirm_password, full_name]):
            flash("All fields are required", "error")
            return render_template("auth/database_register.html")

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("auth/database_register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long", "error")
            return render_template("auth/database_register.html")

        # Check if user already exists
        if User.find_by_username(username):
            flash("Username already exists", "error")
            return render_template("auth/database_register.html")

        if User.find_by_email(email):
            flash("Email already registered", "error")
            return render_template("auth/database_register.html")

        # Create user
        require_verification = current_app.config.get(
            "REQUIRE_EMAIL_VERIFICATION", True
        )
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=UserRole.USER,  # Default role for new registrations
            auth_method=AuthMethod.DATABASE,
            is_active=True,
            email_verified=not require_verification,  # Skip verification if disabled
        )
        user.set_password(password)

        # Generate email verification token if required
        if require_verification:
            verification_token = user.generate_email_verification_token()
            # TODO: Send email verification (for now, just log it)
            current_app.logger.info(
                f"Email verification token for {email}: {verification_token}"
            )

        user.save()

        # Log the registration
        AuditLog.log_user_action(
            action=AuditAction.CREATE,
            result=AuditResult.SUCCESS,
            user=user,
            ip_address=request.remote_addr,
        )

        if require_verification:
            flash(
                "Registration successful! Please check your email for verification link.",
                "success",
            )
        else:
            flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/database_register.html")


@auth_bp.route("/change-password", methods=["GET", "POST"])
def change_password():
    """Force password change for users who must change their password."""
    user_id = session.get("password_change_user_id")
    if not user_id:
        flash("Invalid access", "error")
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # Validation
        if not all([current_password, new_password, confirm_password]):
            flash("All fields are required", "error")
            return render_template("auth/change_password.html", user=user)

        if not user.check_password(current_password):
            flash("Current password is incorrect", "error")
            return render_template("auth/change_password.html", user=user)

        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return render_template("auth/change_password.html", user=user)

        if len(new_password) < 8:
            flash("Password must be at least 8 characters long", "error")
            return render_template("auth/change_password.html", user=user)

        if new_password == current_password:
            flash("New password must be different from current password", "error")
            return render_template("auth/change_password.html", user=user)

        # Update password
        user.set_password(new_password)
        user.must_change_password = False
        user.save()

        # Remove temporary session data
        session.pop("password_change_user_id", None)

        # Create regular session
        session_token = create_session(user, request.remote_addr)

        # Log the password change
        AuditLog.log_user_action(
            action=AuditAction.UPDATE,
            result=AuditResult.SUCCESS,
            user=user,
            ip_address=request.remote_addr,
            details={"action": "password_changed"},
        )

        flash("Password changed successfully!", "success")
        return redirect(url_for("main.index"))

    return render_template("auth/change_password.html", user=user)


@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    """Verify user email with token."""
    user = User.verify_email_token(token)
    if not user:
        flash("Invalid or expired verification token", "error")
        return redirect(url_for("auth.login"))

    if user.email_verified:
        flash("Email already verified", "info")
        return redirect(url_for("auth.login"))

    user.email_verified = True
    user.email_verification_token = None
    user.email_verification_expires = None
    user.save()

    # Log the verification
    AuditLog.log_user_action(
        action=AuditAction.UPDATE,
        result=AuditResult.SUCCESS,
        user=user,
        ip_address=request.remote_addr,
        details={"action": "email_verified"},
    )

    flash("Email verified successfully! You can now log in.", "success")
    return redirect(url_for("auth.database_login"))


@auth_bp.route("/resend-verification/<uuid:user_id>")
def resend_verification(user_id):
    """Resend email verification link."""
    user = User.query.get_or_404(user_id)

    if user.email_verified:
        flash("Email is already verified", "info")
        return redirect(url_for("auth.login"))

    # Generate new verification token
    verification_token = user.generate_email_verification_token()
    user.save()

    # TODO: Send email verification (for now, just log it)
    current_app.logger.info(
        f"Email verification token for {user.email}: {verification_token}"
    )

    flash(
        "Verification email sent. Please check your email for the verification link.",
        "success",
    )
    return redirect(url_for("auth.login"))


@auth_bp.route("/demo/login", methods=["GET", "POST"])
def demo_login():
    """Demo login for development purposes."""
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        role = request.form.get("role")

        if not email or not username or not role:
            flash("Email, username, and role are required", "error")
            return render_template("auth/demo_login.html")

        try:
            user_role = UserRole(role)
        except ValueError:
            flash("Invalid role selected", "error")
            return render_template("auth/demo_login.html")

        # Find existing user by email or username
        user = User.find_by_email(email) or User.find_by_username(username)
        if not user:
            user = User(
                email=email,
                username=username,
                full_name=request.form.get("full_name", username),
                role=user_role,
                auth_method=AuthMethod.DEMO,
                is_active=True,
                email_verified=True,  # Demo users are automatically verified
            )

            # Handle managed environments for managers
            if user_role == UserRole.MANAGER:
                managed_envs = request.form.getlist("managed_environments")
                user.set_managed_environments(managed_envs)

            user.save()
        else:
            # Update existing user's role if different
            if user.role != user_role:
                user.role = user_role
                if user_role == UserRole.MANAGER:
                    managed_envs = request.form.getlist("managed_environments")
                    user.set_managed_environments(managed_envs)
                else:
                    user.set_managed_environments([])
                user.save()

        # Create session
        session_token = create_session(user, request.remote_addr)

        # Log the login
        AuditLog.log_user_action(
            action=AuditAction.LOGIN,
            result=AuditResult.SUCCESS,
            user=user,
            ip_address=request.remote_addr,
            session_id=session_token,
        )

        flash(f"Welcome, {user.full_name}! ({user.role_display_name})", "success")
        return redirect(url_for("main.index"))

    return render_template("auth/demo_login.html")


@auth_bp.route("/saml/acs", methods=["POST"])
def saml_acs():
    """SAML Assertion Consumer Service."""
    # This would handle the SAML response from the IdP
    # For now, return an error message
    flash("SAML ACS not yet implemented", "error")
    return redirect(url_for("auth.login"))


@auth_bp.route("/logout")
def logout():
    """Log out the current user."""
    user = get_current_user()
    destroy_session(user, log_logout=True)

    flash("You have been logged out successfully", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile")
def profile():
    """User profile page."""
    if not is_authenticated():
        return redirect(url_for("auth.login"))

    user = get_current_user()
    if not user:
        return redirect(url_for("auth.login"))

    return render_template("auth/profile.html", user=user)


@auth_bp.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    """Edit user profile."""
    if not is_authenticated():
        return redirect(url_for("auth.login"))

    user = get_current_user()
    if not user:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        user.full_name = request.form.get("full_name", user.full_name)
        user.preferred_environment = request.form.get(
            "preferred_environment", user.preferred_environment
        )
        user.timezone = request.form.get("timezone", user.timezone)
        user.save()

        flash("Profile updated successfully", "success")
        return redirect(url_for("auth.profile"))

    return render_template("auth/edit_profile.html", user=user)


# Note: Authentication functions moved to keeper.auth.session
