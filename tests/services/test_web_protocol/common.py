LINK_HTML = (
    '<a id="id_of_link" class="link-class" name="name_of_link" href="http://i_am_a_link.com/" rel="noreferrer">'
    "the text obviously"
    "</a>"
)

# Navigation targets for the history tests. Self-contained on purpose: a real site needs the
# device to be online, and loads at its own pace - back() intermittently still reported the page
# it was leaving, because the navigation had not been reflected in the browsing context yet. A
# data: URL settles synchronously and is reported back verbatim, so the history is exactly what
# the test put there.
PAGE_ONE = "data:text/html,<title>one</title><h1>one</h1>"
PAGE_TWO = "data:text/html,<title>two</title><h1>two</h1>"
