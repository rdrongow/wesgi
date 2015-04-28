CHANGES
=======

0.10 (2015-04-28)
-----------------

- Nothing changed yet.


0.10 (2015-04-28)
-----------------

Features
++++++++

- Add option to forward_headers from original request to middleware


0.9 (2011-07-07)
---------------

Features
++++++++

- Add wesgi.filter_app_factory which can be used by Paste to configure wesgi as
  a filter_app_factory.
- A ``max_object_size`` option for ``wesgi.LRUCache`` to limit the maximum size
  of objects stored.
- Major refactoring to use ``httplib2`` as the backend to get ESI includes. This
  brings along HTTP Caching.
- A memory based implementation of the LRU caching algoritm at ``wesgi.LRUCache``.
- Handle ESI comments.

Bugfixes
++++++++

- Fix bug where regular expression to find ``src:includes`` could take a long time.
- Sigh. Add MANIFEST.in so necessary files end up in the tarball.


0.8 (2011-07-07)
----------------

Features
++++++++

- A ``max_object_size`` option for ``wesgi.LRUCache`` to limit the maximum size
  of objects stored.

0.7 (2011-07-06)
----------------

Features
++++++++

- Major refactoring to use ``httplib2`` as the backend to get ESI includes. This
  brings along HTTP Caching.
- A memory based implementation of the LRU caching algoritm at ``wesgi.LRUCache``.
- Handle ESI comments.

Bugfixes
++++++++

- Fix bug where regular expression to find ``src:includes`` could take a long time.

0.5 (2011-07-04)
----------------

- Initial release.
