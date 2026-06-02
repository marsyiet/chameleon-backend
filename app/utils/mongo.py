from bson import ObjectId


def serialize_document(document):

    if not document:
        return None

    document["_id"] = str(
        document["_id"]
    )

    return document


def serialize_documents(
    documents
):

    return [
        serialize_document(doc)
        for doc in documents
    ]