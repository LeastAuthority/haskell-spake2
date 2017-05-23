=============================
Haskell SPAKE2 implementation
=============================

Implementation of SPAKE2 key exchange protocol.

Status
======

Doesn't actually work.
We are in the middle of implementing it.

Goals
=====

* compatibility with `python-spake2 <https://github.com/warner/python-spake2>`_
* (stretch) submit to `cryptonite <https://github.com/haskell-crypto/cryptonite>`_

Non-goals
=========

Right now:

* PAKE2+
* any `Elligator Edition <https://moderncrypto.org/mail-archive/curves/2015/000424.html>`_ variants

How to use it
=============

Right now, you don't—it doesn't work.

If you want to know more, check out the `main module documentation <src/Crypto/Spake2.hs>`_.

Testing for interoperability
----------------------------

Requires the `LeastAuthority interoperability harness <https://github.com/leastauthority/spake2-interop-test>`_.

Assumes that haskell-spake2 has been compiled (``stack build`` will do it)
and that you know where the executable lives (``stack install`` might be helpful here).

.. these instructions are not yet verified

To show that Python works as Side A and Haskell works as Side B:

.. code-block:: console

   $ runhaskell TestInterop.hs ./python-spake2-interop-entrypoint.hs A abc -- /path/to/haskell-spake2-interop-entrypoint B abc
   ["./python-spake2-interop-entrypoint.py","A","abc"]
   ["/path/to/haskell-spake2-interop-entrypoint","B","abc"]
   A's key: 8a2e19664f0a2bc6e446d2c44900c67604fe42f6d7e0a1328a5253b21f4131a5
   B's key: 8a2e19664f0a2bc6e446d2c44900c67604fe42f6d7e0a1328a5253b21f4131a5
   Session keys match.

**Note**: if you want to run ``runhaskell`` with ``stack``,
you will need to invoke it like::

   stack runhaskell TestInterop.hs -- ./python-spake2-interop-entrypoint.hs A abc -- /path/to/haskell-spake2-interop-entrypoint B abc

Current results look like:

.. code-block:: console

   $ stack runhaskell TestInterop.hs -- ./python-spake2-interop-entrypoint.py A abc -- ~/.local/bin/haskell-spake2-interop-entrypoint B abc
   ["./python-spake2-interop-entrypoint.py","A","abc"]
   ["/Users/jml/.local/bin/haskell-spake2-interop-entrypoint","B","abc"]
   Traceback (most recent call last):
     File "./python-spake2-interop-entrypoint.py", line 28, in <module>
       key = s.finish(msg_in)
     File "/Users/jml/Library/Python/2.7/lib/python/site-packages/spake2/spake2.py", line 108, in finish
       inbound_elem = g.bytes_to_element(self.inbound_message)
     File "/Users/jml/Library/Python/2.7/lib/python/site-packages/spake2/ed25519_group.py", line 16, in bytes_to_element
       return ed25519_basic.bytes_to_element(b)
     File "/Users/jml/Library/Python/2.7/lib/python/site-packages/spake2/ed25519_basic.py", line 348, in bytes_to_element
       raise ValueError("element is not in the right group")
   ValueError: element is not in the right group
   TestInterop.hs: fd:15: hGetLine: end of file

Which indicates that we are using the wrong group.
Which is why we say that haskell-spake2 doesn't work.


Contributing
============

We use `stack <https://docs.haskellstack.org/en/stable/GUIDE/>`_ for building and testing.

High-quality documentation with examples is very strongly encouraged,
because this stuff is pretty hard to figure out, and we need all the help we can get.
