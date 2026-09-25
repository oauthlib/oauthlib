"""
oauthlib.aio
~~~~~~~~~~~~

Small helpers shared by the async server-side implementation.

The server-side of oauthlib (endpoints, grant types, token handlers and the
``RequestValidator`` interfaces) is ``async``. Storage-backed hooks are
awaited, so a validator can use an async database driver such as SQLAlchemy's
``AsyncSession`` without blocking the event loop.
"""
import inspect

__all__ = ['AsyncInterfaceMixin', 'maybe_await']


async def maybe_await(value):
    """Return ``value``, awaiting it first if it is awaitable.

    Used for user-supplied *hooks* (custom validators, code/token modifiers,
    token generators, ``expires_in`` callables) which may be written either as
    plain functions or as coroutine functions.

    ``RequestValidator`` methods are *not* routed through this helper; they
    are part of a typed interface and must be ``async def``.
    """
    if inspect.isawaitable(value):
        return await value
    return value


def _is_async_callable(obj):
    if isinstance(obj, (staticmethod, classmethod)):
        obj = obj.__func__
    if inspect.iscoroutinefunction(obj):
        return True
    call = getattr(type(obj), '__call__', None)
    return call is not None and inspect.iscoroutinefunction(call)


class AsyncInterfaceMixin:
    """Enforce that subclasses keep ``async`` methods ``async``.

    Any method declared ``async def`` on a class of the interface must still
    resolve to a coroutine function on every subclass, whether the override
    is defined on the subclass itself, inherited from a mixin that precedes
    the interface in the MRO, or wrapped as a ``staticmethod``/``classmethod``.
    Otherwise ``TypeError`` is raised when the subclass is defined.

    Why: the library ``await``s every validator call. A synchronous override
    would either crash at request time (``bool`` is not awaitable) or, if it
    were ever called without ``await``, return a truthy coroutine object and
    silently pass validation. Failing at import time is the safest option.
    """

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        interface_methods = {}
        for base in reversed(cls.__mro__[1:]):
            if not (isinstance(base, type) and issubclass(base, AsyncInterfaceMixin)):
                continue
            for name, attr in vars(base).items():
                if not name.startswith('__') and inspect.iscoroutinefunction(attr):
                    interface_methods[name] = base
        for name, declared_on in interface_methods.items():
            resolved = inspect.getattr_static(cls, name)
            if not callable(resolved) and not isinstance(resolved, (staticmethod, classmethod)):
                continue
            if not _is_async_callable(resolved):
                owner = next((k for k in cls.__mro__ if name in vars(k)), cls)
                raise TypeError(
                    '{}.{} (defined on {}) overrides an async method of {} and '
                    'must be declared with "async def".'.format(
                        cls.__qualname__, name, owner.__qualname__,
                        declared_on.__qualname__))
