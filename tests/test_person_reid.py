from PIL import Image

from ip2domain.core.person_reid import (_required_similarity, assign_identities,
                                        assign_identities_stateless,
                                        get_identity_observations, identity_count,
                                        reset_identities)


def test_anonymous_reid_reuses_visual_identity_and_separates_colours(tmp_path):
    first = tmp_path / "first.jpg"
    second = tmp_path / "second.jpg"
    Image.new("RGB", (80, 160), (15, 25, 210)).save(first)
    Image.new("RGB", (80, 160), (210, 25, 15)).save(second)
    detection = [{"bbox": [0, 0, 80, 160]}]

    reset_identities()
    original = assign_identities(first, detection, "I-1-1")
    repeated = assign_identities(first, detection, "I-2-1")
    different = assign_identities(second, detection, "I-3-1")

    assert original[0]["matched"] is False
    assert repeated[0]["matched"] is True
    assert repeated[0]["person_id"] == original[0]["person_id"]
    assert different[0]["person_id"] != original[0]["person_id"]
    observations = get_identity_observations(original[0]["person_id"])
    assert {item["camera_id"] for item in observations} == {"I-1-1", "I-2-1"}
    reset_identities()


def test_grayscale_reid_requires_near_identical_similarity():
    assert _required_similarity(0.01, 0.50) == 0.995
    assert _required_similarity(0.20, 0.50) == 0.985


def test_stateless_reid_releases_gallery(tmp_path):
    image = tmp_path / "person.jpg"
    Image.new("RGB", (80, 160), (15, 25, 210)).save(image)
    identities, states = assign_identities_stateless(
        image, [{"bbox": [0, 0, 80, 160]}], "I-1-1", [])

    assert identities[0]["person_id"] == "person-1"
    assert states[0]["person_id"] == "person-1"
    assert identity_count() == 0
