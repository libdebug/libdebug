const sphinx_code_tabs_onclick = function(clicked) {
  const tabid = clicked.dataset.id;
  const tabgroup = clicked.parentNode.parentNode.dataset.tabgroup;
  const books = [];

  if (tabgroup) {
    for (const book of document.querySelectorAll("div.tabs")) {
      if (book.dataset.tabgroup == tabgroup) {
        books.push(book);
      }
    }
  }
  else {
    books.push(clicked.parentNode.parentNode);
  }

  for (const book of books) {
    const select = book.children[0];
    for (const button of select.children) {
      button.classList.toggle('selected', button.dataset.id == tabid);
    }
    for (const page of book.children) {
      if (page.hasAttribute('data-id')) {
        page.classList.toggle('selected', page.dataset.id == tabid);
      }
    }
  }

};
