import threading

global_thread_local = threading.local()


class ThreadContainer(object):

    @staticmethod
    def get():
        return global_thread_local

    @staticmethod
    def clear():
        thread_local = ThreadContainer.get()
        thread_local.__dict__.clear()

    @staticmethod
    def delete_value(key):
        thread_local = ThreadContainer.get()
        if key in thread_local.__dict__:
            thread_local.__dict__.pop(key)

    @staticmethod
    def set_value(key, value):
        thread_local = ThreadContainer.get()
        setattr(thread_local, key, value)

    @staticmethod
    def get_value(key):
        thread_local = ThreadContainer.get()
        return getattr(thread_local, key, None)

    @staticmethod
    def get_current_user():
        user = ThreadContainer.get_value('user')
        if user:
            return user
        request = ThreadContainer.get_value('request')
        if request:
            return request.user
        return None

    @staticmethod
    def get_current_user_id():
        user_id = ThreadContainer.get_value('user_id')
        if user_id:
            return user_id
        user = ThreadContainer.get_current_user()
        if user:
            return user.id
        return None
