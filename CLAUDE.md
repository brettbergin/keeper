# Claude Code Project Configuration

This file contains project-specific information and patterns for Claude Code to understand how to work with this codebase effectively.

## Project Overview

**Project Name**: Keeper - Enterprise Secret Management
**Type**: Flask web application
**Language**: Python
**Frontend**: HTML/CSS/JavaScript with Jinja2 templates
**Database**: SQLite (development)

## Repository Structure & Patterns

### Core Directories
- `keeper/` - Main application package
- `keeper/views/` - Flask route handlers
- `keeper/models/` - Database models
- `keeper/auth/` - Authentication and authorization
- `templates/` - Jinja2 HTML templates
- `static/` - CSS, JavaScript, and static assets
- `migrations/` - Database migration files

### New Documentation Pattern: `/specs/`

The `specs/` directory is the centralized location for all design patterns, specifications, and project documentation:

```
specs/
├── bugs/           # Bug reports and issue tracking
├── patterns/       # Design patterns and coding standards (future)
├── api/           # API specifications (future)
├── architecture/  # System architecture docs (future)
└── testing/       # Test plans and strategies (future)
```

#### Bug Tracking Pattern: `/specs/bugs/`

- **Purpose**: Store detailed bug reports and issue documentation
- **Naming Convention**: `{component}-{issue-type}-{YYYY-MM-DD}.md`
- **Format**: Structured markdown with sections for impact, reproduction, and fixes
- **Benefits**:
  - Persistent issue tracking outside of GitHub issues
  - Detailed technical context for future developers
  - Historical record of problems and solutions

**Example bug report structure**:
- Executive Summary
- Critical/Major/Minor Issues breakdown
- Technical details with stack traces
- Working functionality confirmation
- Recommended fixes with priorities
- Testing environment details

## Development Commands

### Running the Application
```bash
make run          # Start development server at localhost:8989
```

### Testing
- Use the demo login system with predefined user profiles
- Admin user: `admin@company.com` / Administrator role
- Access via: http://localhost:8989/auth/demo/login

## Common Issues & Solutions

### Missing Templates
- **Pattern**: `jinja2.exceptions.TemplateNotFound` errors
- **Location**: Usually in `templates/` directory
- **Fix**: Create missing template files following existing patterns

### JavaScript Validation
- **Pattern**: Form validation errors in browser console
- **Location**: Static JavaScript files
- **Impact**: Usually non-blocking, forms still submit

## Code Patterns

### Authentication
- Demo login system available for development
- Role-based access control with decorators
- Profile management through `/auth/profile`

### Admin Functionality
- Centralized admin panel at `/admin/`
- Permission-based access control
- System health monitoring and metrics

### Secret Management
- CRUD operations for secrets
- Environment-based organization
- Synchronization with external services (AWS, Vault)

## Debugging Tips

1. **Template Errors**: Check `templates/` directory structure
2. **Permission Errors**: Verify user role and login status
3. **Database Issues**: Check SQLite file permissions
4. **JavaScript Errors**: Check browser console for client-side issues

## Future Specifications

As the project grows, add additional spec directories:
- `specs/patterns/` - Coding standards and design patterns
- `specs/api/` - REST API documentation
- `specs/architecture/` - System design documents
- `specs/testing/` - Test plans and automation strategies

---

**Last Updated**: 2025-09-20
**Maintained By**: Development Team
**Claude Code Version**: Compatible with current implementation