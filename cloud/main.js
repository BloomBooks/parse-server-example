require("./emails.js"); // allows email-specific could functions to be defined

Parse.Cloud.define("hello", function(req, res) {
    var book = {
        title: "the title",
        uploader: "the uploader",
        copyright: "the copyright",
        license: "the license",
        bookId: "theBookId"
    };
    res.success("Hi");
    console.log("bloom-parse-server cloud-code: hello function");
});

Parse.Cloud.define("testDB", function(req, res) {
    console.log("bloom-parse-server cloud-code: testDB");
    try {
        console.log(
            "bloom-parse-server cloud-code: testDB: trying to read GameScore"
        );
        var GameScore = Parse.Object.extend("GameScore");
        var query = new Parse.Query(GameScore);
        query.count({
            success: function(gameScore) {
                console.log(
                    "bloom-parse-server cloud-code: testDB: GameScore read succeeded"
                );
            },
            error: function(object, error) {
                console.log(
                    "bloom-parse-server cloud-code: testDB: GameScore read failed: " +
                        error
                );
            }
        });
    } catch (ex) {
        console.log(
            "bloom-parse-server cloud-code: testDB: testDB GameScore read threw exception: " +
                ex
        );
    }

    try {
        var parseClass = Parse.Object.extend("testDB");
        var instance = new parseClass();
        instance.set("test", "foo");
        console.log("bloom-parse-server cloud-code: testDB: writing...");
        instance.save(null, {
            useMasterKey: true,
            success: function(newObj) {
                console.log(
                    "bloom-parse-server cloud-code: testDB: save succeeded"
                );
            },
            error: function(error) {
                console.log(
                    "bloom-parse-server cloud-code: testDB: save failed" + error
                );
            }
        });
    } catch (error) {
        console.log(
            "bloom-parse-server cloud-code: testDB: testDB failed: " + error
        );
        res.error("write failed: " + error);
    }
    res.success(
        "This function is not sophisticated enough to wait for async calls. Check server log to verify it completed."
    );
});

// This function will call save on every book. This is useful for
// applying the functionality in beforeSaveBook to every book,
// particularly updating the tags and search fields.
Parse.Cloud.define("saveAllBooks", function(request, response) {
    // Query for all books
    var query = new Parse.Query("books");
    query
        .each(function(book) {
            book.set("updateSource", "saveAllBooks"); // very important so we don't add system:incoming tag
            return book.save(null, { useMasterKey: true }).then(
                function() {},
                function(error) {
                    console.log("book.save failed: " + error);
                    response.error("book.save failed: " + error);
                }
            );
        })
        .then(
            function() {
                // Set the job's success status
                response.success("Update completed successfully.");
            },
            function(error) {
                // Set the job's error status
                response.error(
                    "Uh oh, something went wrong in saveAllBooks: " + error
                );
            }
        );
});

// This job will remove any language records which currently do not have any books which use them.
// The purpose is to keep BloomLibrary.org from displaying languages with no books.
// This is scheduled on Azure under bloom-library-maintenance.
// You can also run it manually via REST:
// curl -X POST -H "X-Parse-Application-Id: <insert app ID>" -H "X-Parse-Master-Key: <insert master key>" -d '{}' https://bloom-parse-server-develop.azurewebsites.net/parse/functions/removeUnusedLanguages
// (In theory, the -d '{}' shouldn't be needed because we are not passing any parameters, but it doesn't work without it.)
Parse.Cloud.define("removeUnusedLanguages", function(request, response) {
    console.log("entering bloom-parse-server main.js removeUnusedLanguages");

    var allLangQuery = new Parse.Query("language");
    allLangQuery.limit(1000000); // default is 100, supposedly. We want all of them.
    allLangQuery
        .find()
        .then(function(languages) {
            var promise = Parse.Promise.as();
            for (var i = 0; i < languages.length; i++) {
                // Use IIFE to pass the correct language down
                (function() {
                    var lang = languages[i];
                    var bookQuery = new Parse.Query("books");
                    bookQuery.equalTo("langPointers", lang);
                    promise = promise.then(function() {
                        return bookQuery.count().then(function(count) {
                            if (count === 0) {
                                console.log(
                                    "Deleting language " +
                                        lang.get("name") +
                                        " because no books use it."
                                );
                                return lang.destroy({
                                    useMasterKey: true,
                                    success: function() {
                                        console.log("Deletion successful.");
                                    },
                                    error: function(error) {
                                        console.log(
                                            "Deletion failed: " + error
                                        );
                                    }
                                });
                            }
                        });
                    });
                })();
            }
            return promise;
        })
        .then(
            function() {
                response.success(
                    "removeUnusedLanguages completed successfully."
                );
            },
            function(error) {
                response.error("Error in removeUnusedLanguages: " + error);
            }
        );
});

// This job will remove any bookshelf records which currently do not have any books which use them.
// The purpose is to keep BloomLibrary.org from displaying bookshelves with no books.
// This is scheduled on Azure under bloom-library-maintenance.
// You can also run it manually via REST:
// curl -X POST -H "X-Parse-Application-Id: <insert app ID>" -H "X-Parse-Master-Key: <insert master key>" -d '{}' https://bloom-parse-server-develop.azurewebsites.net/parse/functions/removeUnusedBookshelves
// (In theory, the -d '{}' shouldn't be needed because we are not passing any parameters, but it doesn't work without it.)
Parse.Cloud.define("removeUnusedBookshelves", function(request, response) {
    console.log("entering bloom-parse-server main.js removeUnusedBookshelves");

    var allShelvesQuery = new Parse.Query("bookshelf");
    allShelvesQuery.limit(1000000); // default is 100, supposedly. We want all of them.
    allShelvesQuery
        .find()
        .then(function(shelves) {
            var promise = Parse.Promise.as();
            for (var i = 0; i < shelves.length; i++) {
                // Use IIFE to pass the correct bookshelf down
                (function() {
                    var shelf = shelves[i];
                    var bookQuery = new Parse.Query("books");
                    bookQuery.equalTo("tags", "bookshelf:" + shelf.get("key"));
                    promise = promise.then(function() {
                        return bookQuery.count().then(function(count) {
                            if (count === 0) {
                                console.log(
                                    "Deleting bookshelf " +
                                        shelf.get("key") +
                                        " because no books use it."
                                );
                                return shelf.destroy({
                                    useMasterKey: true,
                                    success: function() {
                                        console.log("Deletion successful.");
                                    },
                                    error: function(error) {
                                        console.log(
                                            "Deletion failed: " + error
                                        );
                                    }
                                });
                            }
                        });
                    });
                })();
            }
            return promise;
        })
        .then(
            function() {
                response.success(
                    "removeUnusedBookshelves completed successfully."
                );
            },
            function(error) {
                response.error("Error in removeUnusedBookshelves: " + error);
            }
        );
});

// A background job to populate usageCounts for languages and tags
// This is scheduled on Azure under bloom-library-maintenance.
// You can also run it manually via REST:
// curl -X POST -H "X-Parse-Application-Id: <insert app ID>" -H "X-Parse-Master-Key: <insert Master key>" -d "{}" https://bloom-parse-server-develop.azurewebsites.net/parse/functions/populateCounts
Parse.Cloud.define("populateCounts", function(request, response) {
    console.log("entering bloom-parse-server main.js populateCounts");
    request.log.info("Starting populateCounts.");

    var counters = { language: {}, tag: {} };

    //Query each tag
    var tagQuery = new Parse.Query("tag");
    tagQuery
        .each(function(tag) {
            //Initial tag counters are 0
            counters.tag[tag.get("name")] = 0;
        })
        .then(function() {
            //Create a book query
            var bookQuery = new Parse.Query("books");
            bookQuery.limit(1000000); // default is 100, supposedly. We want all of them.

            //Analyze a book's tags and languages and increment proper counts
            function incrementBookUsageCounts(books, index) {
                //If we finished all the books, return resolved promise
                if (index >= books.length) {
                    request.log.info("Processed " + books.length + " books.");
                    return Parse.Promise.as();
                }

                var book = books[index];

                //Increment book's languages' counts
                //Since we shouldn't worry about invalid languages,
                //this process needs no requests to the server and may be iterative
                var langPtrs = book.get("langPointers");
                if (langPtrs) {
                    for (var i = 0; i < langPtrs.length; i++) {
                        var onePtr = langPtrs[i];
                        var id = onePtr.id;
                        if (!(id in counters.language)) {
                            counters.language[id] = 0;
                        }
                        counters.language[id]++;
                    }
                }

                var tags = book.get("tags");
                if (tags) {
                    //Recursively increment book's tags' counts
                    return incrementTagUsageCount(tags, 0).then(function() {
                        //Next book
                        return incrementBookUsageCounts(books, index + 1);
                    });
                }

                //Next book (when no tags)
                return incrementBookUsageCounts(books, index + 1);
            }

            //Increment a given tag's count
            function incrementTagUsageCount(tags, index) {
                if (index >= tags.length) {
                    //Base case
                    //Resolved promise
                    return Parse.Promise.as();
                }

                var tagName = tags[index];
                if (tagName.indexOf(":") < 0) {
                    // In previous versions of Bloom, topics came in without the "topic:" prefix
                    tagName = "topic:" + tagName;
                }
                if (tagName in counters.tag) {
                    counters.tag[tagName]++;
                    //Next tag
                    return incrementTagUsageCount(tags, index + 1);
                } else {
                    //If tag is not one already in the database, add the tag to the database
                    counters.tag[tagName] = 1;
                    var parseClass = Parse.Object.extend("tag");
                    var newTag = new parseClass();
                    newTag.set("name", tagName);
                    return newTag.save(null, { useMasterKey: true }).then(
                        function() {
                            console.log("created tag " + tagName);
                            //Next tag
                            return incrementTagUsageCount(tags, index + 1);
                        },
                        function(error) {
                            console.log("newTag.save failed: " + error);
                            response.error("newTag.save failed: " + error);
                        }
                    );
                }
            }

            //Make query, then initialize recursive book analysis; return promise for next then in promise chain
            return bookQuery.find().then(function(results) {
                return incrementBookUsageCounts(results, 0);
            });
        })
        .then(function() {
            function setLangUsageCount(data, index) {
                //When done, return resolved promise
                if (index >= data.length) {
                    request.log.info(`Processed ${data.length} languages.`);
                    return Parse.Promise.as();
                }

                var language = data[index];
                var languageId = language.id;
                language.set("usageCount", counters.language[languageId] || 0);
                return language.save(null, { useMasterKey: true }).then(
                    function() {
                        //Next language
                        return setLangUsageCount(data, index + 1);
                    },
                    function(error) {
                        console.log(
                            `language ${languageId} save failed: ${error}`
                        );
                        response.error(
                            `language ${languageId} save failed: ${error}`
                        );

                        //Next language
                        return setLangUsageCount(data, index + 1);
                    }
                );
            }

            var langQuery = new Parse.Query("language");
            langQuery.limit(100000); // default is 100, supposedly. We want all of them.

            //Cycle through languages, assigning usage counts
            return langQuery.find().then(function(results) {
                //Start recursion
                return setLangUsageCount(results, 0);
            });
        })
        .then(function() {
            function setTagUsageCount(data, index) {
                //Return resolved promise when done
                if (index >= data.length) {
                    request.log.info(`Processed ${data.length} tags.`);
                    return Parse.Promise.as();
                }

                var tag = data[index];
                var tagName = tag.get("name");
                var count = counters.tag[tagName];
                if (count > 0) {
                    tag.set("usageCount", count);
                    return tag.save(null, { useMasterKey: true }).then(
                        function() {
                            // Next tag
                            return setTagUsageCount(data, index + 1);
                        },
                        function(error) {
                            console.log(`tag ${tagName} save failed: ${error}`);
                            response.error(
                                `tag ${tagName} save failed: ${error}`
                            );

                            // Next tag
                            return setTagUsageCount(data, index + 1);
                        }
                    );
                } else {
                    //Destroy tag with count of 0
                    return tag.destroy({ useMasterKey: true }).then(
                        function() {
                            // Next tag
                            return setTagUsageCount(data, index + 1);
                        },
                        function(error) {
                            console.log(
                                `tag ${tagName} destroy failed: ${error}`
                            );
                            response.error(
                                `tag ${tagName} destroy failed: ${error}`
                            );

                            // Next tag
                            return setTagUsageCount(data, index + 1);
                        }
                    );
                }
            }

            var tagQuery2 = new Parse.Query("tag");
            tagQuery2.limit(100000); // default is 100, supposedly. We want all of them.

            //Cycle through tags in database
            return tagQuery2.find().then(function(results) {
                //Begin recursion
                return setTagUsageCount(results, 0);
            });
        })
        .then(
            function() {
                response.success("Tag and Language usage counts updated!");
            },
            function(error) {
                response.error(
                    "populateCounts terminated unsuccessfully with error: " +
                        error
                );
            }
        );
});

// Makes new and updated books have the right search string and ACL.
Parse.Cloud.beforeSave("books", function(request, response) {
    var book = request.object;

    console.log("entering bloom-parse-server main.js beforeSave books");

    // The original purpose of the updateSource field was so we could set system:Incoming on every book
    // when it is uploaded or reuploaded from BloomDesktop without doing so for changes from the datagrid.
    //
    // A beforeSave event for book could occur from at least one of these sources:
    // * BloomDesktop upload or reupload
    // * Bloomlibrary.org datagrid
    // * Bloom harvester
    // * parse dashboard
    //
    // BloomDesktop does not set updateSource -- old Blooms weren't/aren't setting it, so adding it now doesn't help much
    // Bloomlibrary.org datagrid sets updateSource to datagrid or datagrid (admin)
    // Bloom harvester sets it to bloomHarvester
    // parse dashboard also does not set it -- which was an oversight in the design but also has no obvious solution
    //
    // Now, we also want to set the harvestState field to "New" or "Updated" when a book is uploaded or reuploaded.
    // So, if there is no updateSource, and the book doesn't exist, set to "New".
    // If there is no updateSource, and the book does exist, set to "Updated".
    // Unfortunately, this will also happen when changes are made to rows directly through the parse dashboard.
    var updateSource = request.object.get("updateSource");
    if (!updateSource) {
        // Assume (see caveat above) change came from BloomDesktop upload (or reupload)
        book.addUnique("tags", "system:Incoming");
        if (request.object.isNew()) {
            request.object.set("harvestState", "New");
        } else {
            request.object.set("harvestState", "Updated");
        }
    } else {
        // We never want to leave the value set in the database or our logic (described above) won't work
        request.object.unset("updateSource");
    }

    // Bloom 3.6 and earlier set the authors field, but apparently, because it
    // was null or undefined, parse.com didn't try to add it as a new field.
    // When we migrated from parse.com to parse server,
    // we started getting an error because uploading a book was trying to add
    // 'authors' as a new field, but it didn't have permission to do so.
    // In theory, we could just unset the field here:
    // request.object.unset("authors"),
    // but that doesn't prevent the column from being added, either.
    // Unfortunately, that means we simply had to add authors to the schema. (BL-4001)

    var tags = book.get("tags");
    var search = (book.get("title") || "").toLowerCase();
    var index;
    if (tags) {
        for (index = 0; index < tags.length; ++index) {
            var tagName = tags[index];
            var indexOfColon = tagName.indexOf(":");
            if (indexOfColon < 0) {
                // From older versions of Bloom, topics come in without the "topic:" prefix
                tags[index] = tagName = "topic:" + tagName;
                indexOfColon = "topic:".length - 1;
            }
            // We only want to put the relevant information from the tag into the search string.
            // i.e. for region:Asia, we only want Asia. We also exclude system tags.
            // Our current search doesn't handle multi-string searching, anyway, so even if you knew
            // to search for 'region:Asia' (which would never be obvious to the user), you would get
            // a union of 'region' results and 'Asia' results.
            // Other than 'system:', the prefixes are currently only used to separate out the labels
            // in the sidebar of the browse view.
            if (tagName.startsWith("system:")) continue;
            var tagNameForSearch = tagName.substr(indexOfColon + 1);
            search = search + " " + tagNameForSearch.toLowerCase();
        }
    }
    request.object.set("tags", tags);
    request.object.set("search", search);

    var creator = request.user;

    if (creator && request.object.isNew()) {
        // created normally, someone is logged in and we know who, restrict access
        var newACL = new Parse.ACL();
        // According to https://parse.com/questions/beforesave-user-set-permissions-for-self-and-administrators,
        // a user can always write their own object, so we don't need to permit that.
        newACL.setPublicReadAccess(true);
        newACL.setRoleWriteAccess("moderator", true); // allows moderators to delete
        newACL.setWriteAccess(creator, true);
        request.object.setACL(newACL);
    }
    response.success();
});

Parse.Cloud.afterSave("books", function(request) {
    // We no longer wish to automatically create bookshelves.
    // It is too easy for a user (or even us mistakenly) to create them.
    // const bookshelfPrefix = "bookshelf:";
    // var book = request.object;
    // book.get("tags")
    //     .filter(function(element) {
    //         return element.indexOf(bookshelfPrefix) > -1;
    //     })
    //     .map(function(element) {
    //         return element.substr(bookshelfPrefix.length);
    //     })
    //     .forEach(function(key) {
    //         var Bookshelf = Parse.Object.extend("bookshelf");
    //         var query = new Parse.Query(Bookshelf);
    //         query.equalTo("key", key);
    //         query.count({
    //             success: function(count) {
    //                 if (count == 0) {
    //                     //Create a new bookshelf to contain this book with default properties
    //                     var bookshelf = new Bookshelf();
    //                     bookshelf.set("key", key);
    //                     bookshelf.set("englishName", key);
    //                     bookshelf.set("normallyVisible", false);
    //                     bookshelf.save(null, { useMasterKey: true }).then(
    //                         function() {},
    //                         function(error) {
    //                             console.log("bookshelf.save failed: " + error);
    //                             response.error(
    //                                 "bookshelf.save failed: " + error
    //                             );
    //                         }
    //                     );
    //                 }
    //             },
    //             error: function(error) {
    //                 console.log("get error: " + error);
    //             }
    //         });
    //     });

    try {
        //send email if this didn't exist before
        // this seemed to work locally, but not on the azure production server,
        // and has been the subject of many bug reports over the years
        //          objectExisted = request.object.existed();
        // so we are working around it this way:
        var createdAt = request.object.get("createdAt");
        var updatedAt = request.object.get("updatedAt");
        var objectExisted = createdAt.getTime() != updatedAt.getTime();

        console.log(
            "afterSave email handling request.object.existed():" +
                request.object.existed()
        );
        console.log(
            "afterSave email handling createdAt:" +
                createdAt +
                " updatedAt:" +
                updatedAt +
                " objectExisted:" +
                objectExisted
        );
        if (!objectExisted) {
            var emailer = require("./emails.js");
            emailer
                .sendBookSavedEmailAsync(book)
                .then(function() {
                    console.log("xBook saved email notice sent successfully.");
                })
                .catch(function(error) {
                    console.log(
                        "ERROR: 'Book saved but sending notice email failed: " +
                            error
                    );
                    // We leave it up to the code above that is actually doing the saving to declare
                    // failure (response.error) or victory (response.success), we stay out of it.
                });
        }
    } catch (error) {
        console.log("aftersave email handling error: " + error);
    }
});

Parse.Cloud.afterSave("downloadHistory", function(request) {
    //Parse.Cloud.useMasterKey();
    console.log(
        "entering bloom-parse-server main.js afterSave downloadHistory"
    );
    var entry = request.object;
    var bookId = entry.get("bookId");

    var booksClass = Parse.Object.extend("books");
    var query = new Parse.Query(booksClass);

    query.get(bookId, {
        success: function(book) {
            var currentDownloadCount = book.get("downloadCount") || 0;
            book.set("downloadCount", currentDownloadCount + 1);
            book.set("updateSource", "incrementDownloadCount"); // very important so we don't add system:incoming tag
            book.save(null, { useMasterKey: true }).then(
                function() {},
                function(error) {
                    console.log("book.save failed: " + error);
                    response.error("book.save failed: " + error);
                }
            );
        },
        error: function(object, error) {
            console.log("get error: " + error);
        }
    });
});

// Return the books that should be shown in the default browse view.
// Currently this is those in the Featured bookshelf, followed by all the others.
// Each group is sorted alphabetically by title.
Parse.Cloud.define("defaultBooks", function(request, response) {
    console.log("bloom-parse-server main.js define defaultBooks function");
    var first = request.params.first;
    var count = request.params.count;
    var includeOutOfCirculation = request.params.includeOutOfCirculation;
    var allLicenses = request.params.allLicenses == true;
    var contentQuery = new Parse.Query("books");
    contentQuery.equalTo("tags", "bookshelf:Featured");
    if (!includeOutOfCirculation)
        contentQuery.containedIn("inCirculation", [true, undefined]);
    contentQuery.include("langPointers");
    contentQuery.include("uploader");
    if (!allLicenses) contentQuery.startsWith("license", "cc-");
    contentQuery.ascending("title");
    contentQuery.limit(1000000); // default is 100, supposedly. We want all of them.
    contentQuery.find({
        success: function(shelfBooks) {
            var results = [];
            var shelfIds = Object.create(null); // create an object with no properties to be a set
            var resultIndex = 0;
            for (var i = 0; i < shelfBooks.length; i++) {
                if (resultIndex >= first && resultIndex < first + count) {
                    results.push(shelfBooks[i]);
                }
                resultIndex++;
                shelfIds[shelfBooks[i].id] = true; // put in set
            }
            var skip = 0;
            // This function implements a query loop by calling itself inside each
            // promise fulfilment if more results are needed.
            var runQuery = function() {
                var allBooksQuery = new Parse.Query("books");
                if (!includeOutOfCirculation)
                    allBooksQuery.containedIn("inCirculation", [
                        true,
                        undefined
                    ]);
                allBooksQuery.include("langPointers");
                allBooksQuery.include("uploader");
                if (!allLicenses) allBooksQuery.startsWith("license", "cc-");
                allBooksQuery.ascending("title");
                allBooksQuery.skip(skip); // skip the ones we already got
                // REVIEW: would this work? Would it speed things up?  allBooksQuery.limit(count);
                // It looks like maybe we're getting all 1000 books and then only
                // copying "count" books into the results.

                allBooksQuery.find({
                    success: function(allBooks) {
                        skip += allBooks.length; // skip these ones next iteration
                        for (
                            var i = 0;
                            i < allBooks.length && resultIndex < first + count;
                            i++
                        ) {
                            if (!(allBooks[i].id in shelfIds)) {
                                if (resultIndex >= first) {
                                    results.push(allBooks[i]);
                                }
                                resultIndex++;
                            }
                        }
                        if (
                            allBooks.length == 0 ||
                            resultIndex >= first + count
                        ) {
                            // either we can't get any more, or we got all we need.
                            response.success(results);
                            return;
                        }
                        runQuery(); // launch another iteration.
                    },
                    error: function() {
                        response.error("failed to find all books");
                    }
                });
            };
            runQuery(); // start the recursive loop.
        },
        error: function() {
            response.error("failed to find books of featured shelf");
        }
    });
});

// This function is used to set up the fields used in the bloom library.
// Adding something here should be the ONLY way fields and classes are added to parse.com.
// After adding one, it is recommended that you first deploy the modified cloud code
// to a test project, run it, and verify that the result are as expected.
// Then try on the bloomlibrarysandbox (where you should also develop and test the
// functionality that uses the new fields).
// Finally deploy and run on the live database.
// For more information about deploying, see the main README.md.
//
// Currently this will not delete fields or tables; if you want to do that it will have to be
// by hand.
//
// Run this function from a command line like this (with the appropriate keys for the application inserted)
// curl -X POST -H "X-Parse-Application-Id: <App ID>" -H "X-Parse-Master-Key: <Master Key>" https://bloom-parse-server-production.azurewebsites.net/parse/functions/setupTables/
//
// Alternatively, you can use the parse server's dashboard's API Console to run the function:
// parsedashboard.bloomlibrary.org or dev-parsedashboard.bloomlibrary.org.
// Go to the API Console. type=POST, endpoint="functions/setupTables", useMasterKey=yes. Click Send Query.
//
// NOTE: There is reason to believe that using this function to add columns of type Object does not work
// and that they must be added manually (in the dashboard) instead.
Parse.Cloud.define("setupTables", function(request, response) {
    // Required BloomLibrary classes/fields
    // Note: code below currently requires that 'books' is first.
    // Current code supports only String, Boolean, Number, Date, Array, Pointer<_User/Book/appDetailsInLanguage>,
    // and Relation<books/appDetailsInLanguage>.
    // It would be easy to generalize the pointer/relation code provided we can organize so that classes that are
    // the target of relations or pointers occur before the fields targeting them.
    // This is because the way we 'create' a field is to create an instance of the class that has that field.
    // These instances can also be conveniently used as targets when creating instances of classes
    // that refer to them.
    console.log("bloom-parse-server main.js define setupTables function");
    var classes = [
        {
            name: "version",
            fields: [{ name: "minDesktopVersion", type: "String" }]
        },
        {
            name: "books",
            fields: [
                { name: "allTitles", type: "String" },
                // For why the 'authors' field is needed, see http://issues.bloomlibrary.org/youtrack/issue/BL-4001
                { name: "authors", type: "Array" },
                { name: "baseUrl", type: "String" },
                { name: "bookInstanceId", type: "String" },
                { name: "bookLineage", type: "String" },
                { name: "bookOrder", type: "String" },
                { name: "bookletMakingIsAppropriate", type: "Boolean" },
                { name: "copyright", type: "String" },
                { name: "credits", type: "String" },
                { name: "currentTool", type: "String" },
                { name: "downloadCount", type: "Number" },
                { name: "downloadSource", type: "String" },
                { name: "experimental", type: "Boolean" },
                { name: "folio", type: "Boolean" },
                { name: "formatVersion", type: "String" },
                { name: "inCirculation", type: "Boolean" },
                { name: "isbn", type: "String" },
                { name: "langPointers", type: "Array" },
                { name: "languages", type: "Array" },
                { name: "librarianNote", type: "String" },
                { name: "license", type: "String" },
                { name: "licenseNotes", type: "String" },
                { name: "pageCount", type: "Number" },
                { name: "readerToolsAvailable", type: "Boolean" },
                { name: "search", type: "String" },
                { name: "show", type: "Object" },
                { name: "suitableForMakingShells", type: "Boolean" },
                { name: "suitableForVernacularLibrary", type: "Boolean" },
                { name: "summary", type: "String" },
                { name: "tags", type: "Array" },
                { name: "thumbnail", type: "String" },
                { name: "title", type: "String" },
                { name: "tools", type: "Array" },
                { name: "updateSource", type: "String" },
                { name: "uploader", type: "Pointer<_User>" },
                { name: "lastUploaded", type: "Date" },
                { name: "leveledReaderLevel", type: "Number" },
                { name: "country", type: "String" },
                { name: "province", type: "String" },
                { name: "district", type: "String" },
                { name: "features", type: "Array" },
                // Fields required by Harvester
                { name: "harvestState", type: "String" },
                { name: "harvesterId", type: "String" },
                { name: "harvesterMajorVersion", type: "Number" },
                { name: "harvesterMinorVersion", type: "Number" },
                { name: "harvestStartedAt", type: "Date" },
                { name: "harvestLog", type: "Array" },
                // End fields required by Harvester
                { name: "internetLimits", type: "Object" },
                { name: "importedBookSourceUrl", type: "String" }
            ]
        },
        {
            name: "bookshelf",
            fields: [
                { name: "englishName", type: "String" },
                { name: "key", type: "String" },
                { name: "normallyVisible", type: "Boolean" },
                { name: "owner", type: "Pointer<_User>" },
                { name: "category", type: "String" }
            ]
        },
        {
            name: "downloadHistory",
            fields: [
                { name: "bookId", type: "String" },
                { name: "userIp", type: "String" },
                { name: "userName", type: "String" }
            ]
        },
        {
            name: "language",
            fields: [
                { name: "ethnologueCode", type: "String" },
                { name: "isoCode", type: "String" },
                { name: "name", type: "String" },
                { name: "englishName", type: "String" },
                //Usage count determined daily per Parse.com job
                { name: "usageCount", type: "Number" }
            ]
        },
        {
            name: "tag",
            fields: [
                { name: "name", type: "String" },
                //Usage count determined daily per Parse.com job
                { name: "usageCount", type: "Number" }
            ]
        },
        {
            name: "relatedBooks",
            fields: [{ name: "books", type: "Array" }]
        },
        {
            name: "appDetailsInLanguage",
            fields: [
                { name: "androidStoreLanguageIso", type: "String" },
                { name: "title", type: "String" },
                { name: "shortDescription", type: "String" },
                { name: "fullDescription", type: "String" }
            ]
        },
        {
            name: "appSpecification",
            fields: [
                { name: "bookVernacularLanguageIso", type: "String" },
                { name: "defaultStoreLanguageIso", type: "String" },
                { name: "buildEngineJobId", type: "String" },
                { name: "colorScheme", type: "String" },
                { name: "icon1024x1024", type: "String" },
                { name: "featureGraphic1024x500", type: "String" },
                { name: "details", type: "Relation<appDetailsInLanguage>" },
                { name: "owner", type: "Pointer<_User>" },
                { name: "packageName", type: "String" }
            ]
        },
        {
            // must come after the classes it references
            name: "booksInApp",
            fields: [
                { name: "app", type: "Pointer<appSpecification>" },
                { name: "book", type: "Pointer<books>" },
                { name: "index", type: "Integer" }
            ]
        }
    ];

    var ic = 0;
    var aUser = null;
    var aBook = null;
    var anApp = null;
    var aDetail = null;
    // If we're updating a 'live' table, typically we will have locked it down so
    // only with the master key can we add fields or classes.
    //Parse.Cloud.useMasterKey();

    var doOne = function() {
        var className = classes[ic].name;
        var parseClass = Parse.Object.extend(className);
        var instance = new parseClass();
        var val = null;
        var fields = classes[ic].fields;
        for (var ifld = 0; ifld < fields.length; ifld++) {
            var fieldName = fields[ifld].name;
            var fieldType = fields[ifld].type;
            switch (fieldType) {
                case "String":
                    instance.set(fieldName, "someString");
                    break;
                case "Date":
                    instance.set(fieldName, {
                        __type: "Date",
                        iso: "2015-02-15T00:00:00.000Z"
                    });
                    break;
                case "Boolean":
                    instance.set(fieldName, true);
                    break;
                case "Number":
                    instance.set(fieldName, 1);
                    break;
                case "Array":
                    instance.set(fieldName, ["one", "two"]);
                    break;
                case "Pointer<_User>":
                    instance.set(fieldName, aUser);
                    break;
                case "Pointer<books>":
                    // This and next could be generalized if we get a couple more. User would remain special.
                    instance.set(fieldName, aBook);
                    break;
                case "Pointer<appSpecification>":
                    instance.set(fieldName, anApp);
                    break;
                case "Relation<books>":
                    // This and next could be generalized if we have other kinds of relation one day.
                    var target = aBook;
                    var relation = instance.relation(fieldName);
                    relation.add(target);
                    break;
                case "Relation<appDetailsInLanguage>":
                    var target = aDetail;
                    var relation = instance.relation(fieldName);
                    relation.add(target);
                    break;
            }
        }
        instance.save(null, {
            useMasterKey: true,
            success: function(newObj) {
                // remember the new object so we can destroy it later, or use it as a relation target.
                classes[ic].parseObject = newObj;
                // if the class is one of the ones we reference in pointers or relations,
                // remember the appropriate instance for use in creating a sample.
                if (classes[ic].name == "books") {
                    aBook = newObj;
                } else if (classes[ic].name == "appSpecification") {
                    anApp = newObj;
                } else if (classes[ic].name == "appDetailsInLanguage") {
                    aDetail = newObj;
                }
                ic++;
                if (ic < classes.length) {
                    doOne(); // recursive call to the main method to loop
                } else {
                    // Start a new recursive iteration to delete the objects we don't need.
                    ic = 0;
                    deleteOne();
                }
            },
            error: function(error) {
                console.log("instance.save failed: " + error);
                response.error("instance.save failed: " + error);
            }
        });
    };
    var deleteOne = function() {
        // Now we're done, the class and fields must exist; we don't actually want the instances
        var newObj = classes[ic].parseObject;
        newObj.destroy({
            useMasterKey: true,
            success: function() {
                ic++;
                if (ic < classes.length) {
                    deleteOne(); // recursive loop
                } else {
                    cleanup();
                }
            },
            error: function(error) {
                response.error(error);
            }
        });
    };
    var cleanup = function() {
        // We've done the main job...now some details.
        var versionType = Parse.Object.extend("version");
        var query = new Parse.Query("version");
        query.find({
            success: function(results) {
                var version;
                if (results.length >= 1) {
                    // updating an existing project, already has version table and instance
                    version = results[0];
                } else {
                    version = new versionType();
                }
                version.set("minDesktopVersion", "2.0");
                version.save(null, {
                    useMasterKey: true,
                    success: function() {
                        // Finally destroy the spurious user we made.
                        aUser.destroy({
                            useMasterKey: true,
                            success: function() {
                                response.success(
                                    "setupTables ran to completion."
                                );
                            },
                            error: function(error) {
                                response.error(error);
                            }
                        });
                    },
                    error: function(error) {
                        console.log("version.save failed: " + error);
                        response.error("version.save failed: " + error);
                    }
                });
            },
            error: function(error) {
                response.error(error);
            }
        });
    };
    // Create a user, temporarily, which we will delete later.
    // While debugging I got tired of having to manually remove previous "temporary" users,
    // hence each is now unique.
    var rand = parseInt(Math.random() * 10000, 10);
    Parse.User.signUp(
        "zzDummyUserForSetupTables" + rand,
        "unprotected",
        { administrator: false },
        {
            success: function(newUser) {
                aUser = newUser;
                doOne(); // start the recursion.
            },
            error: function(error) {
                response.error(error);
            }
        }
    );
});

// This function expects to be passed params containing an id and JWT token
// from a successful firebase login. It looks for a parse-server identity whose
// username is that same ID. If it finds one, it does nothing...the
// bloomFirebaseAuthAdapter code will simply match up the identities.
// If it does not find a corresponding parse-server identity, it creates
// one.
// The token is not actually currently used. We might decide to authenticate it
// at some point.
Parse.Cloud.define("bloomLink", async function(request, response) {
    try {
        var id = request.params.id;
        //console.log(" bloomLink with request: " + JSON.stringify(request));
        const query = new Parse.Query("User");
        query.equalTo("username", id);
        const results = await query.find({ useMasterKey: true });
        let user;
        if (results.length == 0) {
            //console.log("User not found in bloomLink: " + id);
            // We need a new parse user to correspond to the firebase credentials.
            // We want to make a user with the specified ID. The standard approach
            // to making a user with the specified authData produces a random ID.
            // So, we will use the standard login procedure. This requires a password.
            // This is a (not super secure) approach to producing a random one.
            // No one will ever be able to discover it again, so anything that needs
            // it had better be done now!
            var pw = Math.random()
                .toString(36)
                .slice(-10);
            user = await Parse.User.signUp(id, pw, { email: id });
            //console.log("signed up " + JSON.stringify(user));
        } else {
            user = results[0];
        }
        response.success("got user");
    } catch (e) {
        response.error(e);
    }
    return;
    // The following code saves authData corresponding to the current token.
    // However, we don't actually need any: the bloomFirebaseAuthAdapter is happy to
    // authorize any user given a valid firebase authentication token from the
    // right source, properly encrypted, and for a user with the right email.

    //console.log("bloomLink got user " + JSON.stringify(user));
    // const token = request.params.token;
    // // Note: at one point I set the id field from user.username. That ought to be
    // // the same as id, since we searched for and if necessary created a user with that
    // // username. In fact, however, it was always undefined.
    // const authData = { bloom: { id: id, token: token } };
    // //console.log("bloomLink authdata from params: " + JSON.stringify(authData));

    // // The user object we get is in some bizarre state where stringify indicates it
    // // has an authData property, but user.authData is null. This stringify/parse
    // // converts it into a conventional object that works as expected.
    // user = JSON.parse(JSON.stringify(user));
    // // console.log(
    // //     "bloomLink authdata from user: " + JSON.stringify(user.authData)
    // // );

    // if (!user.authData) {
    //     // console.log(
    //     //     "bloomLink setting user authdata to " + JSON.stringify(authData)
    //     // );
    //     user.set("authData", authData, { useMasterKey: true });
    //     user.save(null, { useMasterKey: true }).then(
    //         () => {
    //             //console.log("bloomLink saved user: " + JSON.stringify(user));
    //             response.success("did it!");
    //         },
    //         error => {
    //             console.log(
    //                 "bloomLink failed to save " + JSON.stringify(error)
    //             );
    //             response.error(error);
    //         }
    //     );
    // } else {
    //     // console.log(
    //     //     "bloomLink found existing authData: " +
    //     //         JSON.stringify(user.authData)
    //     // );
    //     response.success("existing");
    // }
    // Instead of one of the two success responses above, we should now be able to log
    // them in and return a token. That would save the client another http
    // request. But I haven't been able to get it to work. Parse documentation tells
    // how to log in using custom auth with the REST API, but not with the Javascript API.
    // const linkResult = await user.linkWith(user, authData); // fails, linkWith is not a function (even before stringify/parse above)
    // console.log("after login user " + JSON.stringify(user));
    // console.log("after login linkResult " + JSON.stringify(linkResult));
});
