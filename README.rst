iota
====

iota is a Python framework to interact with BMW's ConnectedDrive service. It focuses specifically on "i" vehicles, most especially the i3. Feel free to fork and submit pull requests to better support other models.

The intent is to provide an object-oriented approach to interacting with vehicles. For example, I should be able to check if ``Car.doors.locked`` evaluates to ``True`` or ``False``. If I find out I've left the car unlocked, I can then call ``Car.lock_doors`` to secure it. I can also check on a single door, as in ``Car.doors.driver_front`` to determine its status.

This is Python 3.x code; it is not tested on Python 2.x.

Credit is due to Terence Eden; none of his code is used here but he inspired my original efforts to reverse-engineer the API. You can also find `his repo on GitHub`_.

.. _his repo on GitHub: https://github.com/edent/BMW-i-Remote

Why the name?
-------------

It's the Greek letter for "i" and that's it.
