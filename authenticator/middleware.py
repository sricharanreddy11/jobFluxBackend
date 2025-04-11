from authenticator.thread_container import ThreadContainer


class ThreadUserMiddleware:
    """
    Middleware that sets the current user and request in thread local storage.
    This allows accessing the current user throughout the request lifecycle
    without passing the user object explicitly.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ThreadContainer.clear()

        ThreadContainer.set_value('request', request)

        if hasattr(request, 'user') and request.user.is_authenticated:
            ThreadContainer.set_value('user', request.user)
            ThreadContainer.set_value('user_id', request.user.id)

        response = self.get_response(request)

        ThreadContainer.clear()

        return response